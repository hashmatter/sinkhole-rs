pub use sinkhole_core::{PublicKey, PrivateKey};

pub trait Query {

    fn encrypt(content: [u8], public_key: sinkhole_core::PublicKey);
}