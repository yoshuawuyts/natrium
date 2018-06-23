#![cfg_attr(feature = "nightly", deny(missing_docs))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(test, deny(warnings))]

pub struct ChaCha {
  state: Vec<u32>,
}

impl ChaCha {
  /// Create a new instance.
  pub fn with_state(state: Vec<u32>) -> Self {
    Self { state }
  }

  /// Access the internal state
  #[inline]
  pub fn state (&self) -> &[u32] {
    &self.state
  }

  pub fn quarter_round(&mut self, a: u16, b: u16, c: u16, d: u16) {
    let a = a as usize;
    let b = b as usize;
    let c = c as usize;
    let d = d as usize;

    let (a_res, b_res, c_res, d_res) = quarter_round(
      self.state[a],
      self.state[b],
      self.state[c],
      self.state[d],
    );

    self.state[a] = a_res;
    self.state[b] = b_res;
    self.state[c] = c_res;
    self.state[d] = d_res;
  }
}

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
