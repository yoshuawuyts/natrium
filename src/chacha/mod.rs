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
pub fn chacha20_block(key: &Key, nonce: &[u32], block_count: u32) -> Vec<u32> {
  assert_eq!(nonce.len(), 3);

  let mut state = setup_state(key, nonce, block_count);
  let working_state = rot20(&state);

  for (i, working) in working_state.iter().enumerate() {
    state[i] = state[i].wrapping_add(*working);
  }

  state
}

/// Initialize the chacha state.
#[inline]
pub fn setup_state(key: &Key, nonce: &[u32], block_count: u32) -> Vec<u32> {
  let mut state: Vec<u32> = Vec::with_capacity(16);

  state.push(0x6170_7865_u32);
  state.push(0x3320_646e_u32);
  state.push(0x7962_2d32_u32);
  state.push(0x6b20_6574_u32);

  state.extend_from_slice(key.key());
  state.push(block_count);
  state.extend_from_slice(nonce);

  state
}

/// Apply 20 rounds of chacha.
#[inline]
pub fn rot20(state: &[u32]) -> Vec<u32> {
  let mut working_state = state.to_owned();
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
pub fn qround(state: &mut [u32], a: u16, b: u16, c: u16, d: u16) {
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
