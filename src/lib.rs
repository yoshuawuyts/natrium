#![cfg_attr(feature = "nightly", deny(missing_docs))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(test, deny(warnings))]

extern crate byteorder;
// #[macro_use]
extern crate failure;

pub mod chacha;

/// Result type.
pub type Result<T> = std::result::Result<T, failure::Error>;
