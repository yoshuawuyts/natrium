//! ChaCha20 stream cipher.
//!
//! The ChaCha20 cipher is a high-speed cipher.  It is considerably faster than
//! AES in software-only implementations, making it around three times as fast
//! on platforms that lack specialized AES hardware. ChaCha20 is also not
//! sensitive to timing attacks.

mod key;

pub use self::key::Key;

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
pub fn chacha20_block(
  key: &[u32],
  nonce: &[u32],
  block_count: u32,
) -> Vec<u32> {
  assert_eq!(key.len(), 8);
  assert_eq!(nonce.len(), 3);

  let mut state = setup_state(key, nonce, block_count);
  let working_state = chacha20_rot(&state);

  for (i, working) in working_state.iter().enumerate() {
    state[i] = state[i].wrapping_add(*working);
  }

  state
}

#[inline]
fn setup_state(key: &[u32], nonce: &[u32], block_count: u32) -> Vec<u32> {
  let mut state: Vec<u32> = Vec::with_capacity(16);

  state.push(0x61707865_u32);
  state.push(0x3320646e_u32);
  state.push(0x79622d32_u32);
  state.push(0x6b206574_u32);

  state.extend_from_slice(key);
  state.push(block_count);
  state.extend_from_slice(nonce);

  state
}

#[inline]
fn chacha20_rot(state: &Vec<u32>) -> Vec<u32> {
  let mut working_state = state.clone();
  for _ in 0..10 {
    qround(&mut working_state, 0, 4, 8, 12);
    qround(&mut working_state, 1, 5, 9, 13);
    qround(&mut working_state, 2, 6, 10, 14);
    qround(&mut working_state, 3, 7, 11, 15);
    qround(&mut working_state, 0, 5, 10, 15);
    qround(&mut working_state, 1, 6, 11, 12);
    qround(&mut working_state, 2, 7, 8, 13);
    qround(&mut working_state, 3, 4, 9, 14);
  }
  working_state
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

mod test {
  extern crate byteorder;

  // Follows the IETF spec test data.
  #[test]
  fn qround_test_vector() {
    use super::*;
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

  // Follows the IETF spec test data.
  #[test]
  fn quarter_round_test_vector() {
    use super::*;

    let a = 0x11111111;
    let b = 0x01020304;
    let c = 0x9b8d6f43;
    let d = 0x01234567;

    let (a, b, c, d) = quarter_round(a, b, c, d);

    assert_eq!(a, 0xea2a92f4);
    assert_eq!(b, 0xcb1cf8ce);
    assert_eq!(c, 0x4581472e);
    assert_eq!(d, 0x5881c4bb);
  }

  // Follows the IETF spec test data.
  #[test]
  fn chacha20_block_test_vector() {
    use super::*;

    let key: Vec<u8> = vec![
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];

    let nonce: Vec<u8> = vec![
      0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];

    let key = to_u32(key);
    let nonce = to_u32(nonce);
    let block_count = 1u32;

    let state = setup_state(&key, &nonce, block_count);
    let expected: Vec<u32> = vec![
      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504,
      0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
      0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    ];
    assert_eq!(state, expected, "setup state");

    let working_state = chacha20_rot(&state);
    let expected: Vec<u32> = vec![
      0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f, 0xc4f2d0c7, 0xfc62bb2f,
      0x8fa018fc, 0x3f5ec7b7, 0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
      0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2,
    ];
    assert_eq!(working_state, expected, "20 rotations");

    let res = chacha20_block(&key, &nonce, block_count);
    let expected: Vec<u32> = vec![
      0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033,
      0x9aaa2204, 0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
      0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
    ];
    assert_eq!(res, expected, "block");

    fn to_u32(from: Vec<u8>) -> Vec<u32> {
      use self::byteorder::{ReadBytesExt, LE};
      use std::io::Cursor;

      let max = from.len() / 4;

      let mut state = Vec::with_capacity(max);
      let mut reader = Cursor::new(from);
      for _ in 0..max {
        let byte = reader.read_u32::<LE>().unwrap();
        state.push(byte);
      }

      state
    }
  }
}
