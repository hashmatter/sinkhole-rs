//! The query generation and decryption used by the `sinkhole` library.

pub use sinkhole_core::{PrivateKey, PublicKey};

/// A trait used to encrypt queries and decrypt the results in
/// various cryptographic schemes.
///
/// Implementations of this trait simply use different
/// cryptography libraries for various trade-offs.
pub trait Query {
    fn encrypt(content: &[u8], public_key: sinkhole_core::PublicKey);
    fn decrypt(result: &[u8], private_key: sinkhole_core::PrivateKey);
}
