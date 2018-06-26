use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::convert::AsRef;
use std::io::Cursor;
use Result;

/// ChaCha key.
#[derive(Debug, Clone)]
pub struct Key {
  key: Vec<u32>,
}

impl Key {
  /// Create a new instance from a byte slice.
  pub fn from_bytes(bytes: impl AsRef<Vec<u8>>) -> Result<Self> {
    let bytes = bytes.as_ref();
    let max = bytes.len() / 4;

    let mut key = Vec::with_capacity(max);
    let mut reader = Cursor::new(bytes);
    for _ in 0..max {
      let byte = reader.read_u32::<LE>().expect("Error writing key");
      key.push(byte);
    }
    Ok(Self { key })
  }

  /// Convert into a byte slice.
  pub fn as_bytes(&self) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(self.key.len() * 4);
    for num in &self.key {
      bytes.write_u32::<LE>(*num).expect("Error converting key");
    }
    bytes
  }

  /// Get the key.
  #[inline]
  pub fn key(&self) -> &[u32] {
    &self.key
  }
}
