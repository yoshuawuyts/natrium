use byteorder::{ReadBytesExt, LE};
use std::io::Cursor;

/// ChaCha key.
#[derive(Debug, Clone)]
pub struct Key {
  key: Vec<u32>,
}

impl Key {
  /// Create a new instance bytes a byte slice.
  pub fn from_bytes(bytes: &[u8]) -> Self {
    let max = bytes.len() / 4;

    let mut key = Vec::with_capacity(max);
    let mut reader = Cursor::new(bytes);
    for _ in 0..max {
      let byte = reader.read_u32::<LE>().unwrap();
      key.push(byte);
    }
    Self { key }
  }
}
