extern crate chacha;

use chacha::ChaCha;

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

#[test]
fn quarter_round_chacha() {
  let state = [
    0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
    0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
    0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
    0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
  ];

  let mut inst = ChaCha::with_state(state.to_vec());
  inst.quarter_round(2, 7, 8, 13);

  let expected = [
    0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
    0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
    0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
    0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
  ];
  assert_eq!(inst.state(), &expected);
}
