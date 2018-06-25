extern crate natrium;

use natrium::chacha;

#[test]
fn quarter_round_test_vector() {
  let a = 0x11111111;
  let b = 0x01020304;
  let c = 0x9b8d6f43;
  let d = 0x01234567;

  let (a, b, c, d) = chacha::quarter_round(a, b, c, d);

  assert_eq!(a, 0xea2a92f4);
  assert_eq!(b, 0xcb1cf8ce);
  assert_eq!(c, 0x4581472e);
  assert_eq!(d, 0x5881c4bb);
}
