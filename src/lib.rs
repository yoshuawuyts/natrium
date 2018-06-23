#![cfg_attr(feature = "nightly", deny(missing_docs))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(test, deny(warnings))]

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
