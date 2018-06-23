#![cfg_attr(feature = "nightly", deny(missing_docs))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(test, deny(warnings))]

extern crate byteorder;

use byteorder::{ReadBytesExt, LE};
use std::io::Cursor;

/// Operate on 16 u32 numbers to compute a full ChaCha cypher.
///
/// The internal state is a vector of 16 u32s laid out in memory as:
/// ```txt
/// cccccccc  cccccccc  cccccccc  cccccccc
/// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
/// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
/// bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
///
/// c=constant k=key b=blockcount n=nonce
/// ```
// Each value must be little-endian.
#[inline]
pub fn chacha20_block(key: &[u8], nonce: &[u8], block_count: u32) -> Vec<u32> {
  assert_eq!(key.len(), 256);
  assert_eq!(nonce.len(), 96);

  let mut state = Vec::with_capacity(16);

  // Constants
  state.push(0x61707865);
  state.push(0x3320646e);
  state.push(0x79622d32);
  state.push(0x6b206574);

  let mut reader = Cursor::new(key);
  for _ in 0..8 {
    let byte = reader.read_u32::<LE>().unwrap();
    state.push(byte);
  }

  state.push(block_count);

  let mut reader = Cursor::new(nonce);
  for _ in 0..3 {
    let byte = reader.read_u32::<LE>().unwrap();
    state.push(byte);
  }

  let mut working_state = state.clone();

  for _ in 0..20 {
    qround(&mut working_state, 0, 4, 8, 12);
    qround(&mut working_state, 1, 5, 9, 13);
    qround(&mut working_state, 2, 6, 10, 14);
    qround(&mut working_state, 3, 7, 11, 15);
    qround(&mut working_state, 0, 5, 10, 15);
    qround(&mut working_state, 1, 6, 11, 12);
    qround(&mut working_state, 2, 7, 8, 13);
    qround(&mut working_state, 3, 4, 9, 14);
  }

  for (i, working) in working_state.iter().enumerate() {
    state[i] = state[i].wrapping_add(*working);
  }

  state
}

/// Rotate the internal state by a quarter round.
fn qround(state: &mut Vec<u32>, a: u16, b: u16, c: u16, d: u16) {
  let a = a as usize;
  let b = b as usize;
  let c = c as usize;
  let d = d as usize;

  let (a_res, b_res, c_res, d_res) =
    quarter_round(state[a], state[b], state[c], state[d]);

  state[a] = a_res;
  state[b] = b_res;
  state[c] = c_res;
  state[d] = d_res;
}

/// The basic operation of the ChaCha algorithm.
#[inline]
pub fn quarter_round(
  mut a: u32,
  mut b: u32,
  mut c: u32,
  mut d: u32,
) -> (u32, u32, u32, u32) {
  a = a.wrapping_add(b);
  d ^= a;
  d = d.rotate_left(16);

  c = c.wrapping_add(d);
  b ^= c;
  b = b.rotate_left(12);

  a = a.wrapping_add(b);
  d ^= a;
  d = d.rotate_left(8);

  c = c.wrapping_add(d);
  b ^= c;
  b = b.rotate_left(7);

  (a, b, c, d)
}

#[test]
fn qround_test_vector() {
  let mut state = vec![
    0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f,
    0xd9fc690b, 0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
    0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
  ];

  qround(&mut state, 2, 7, 8, 13);

  let expected = [
    0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f,
    0xd9fc690b, 0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
    0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
  ];

  assert_eq!(state, expected);
}
