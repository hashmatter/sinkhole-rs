//! The core traits and types for the `sinkhole` library.

pub extern crate curve25519_dalek;
extern crate elgamal_ristretto;
extern crate hex;
extern crate rand_core;

pub mod elgamal;
pub mod errors;
pub mod traits;
