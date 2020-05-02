//! The query generation and decryption used by the `sinkhole` library.

extern crate curve25519_dalek;
extern crate elgamal_ristretto;

pub mod elgamal;
pub mod errors;
pub mod traits;
