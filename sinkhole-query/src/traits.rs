//! The query generation and decryption used by the `sinkhole` library.

pub mod query {
    pub trait Query {
        /// Constructs an encrypted query.
        fn new(
            content: &[u8],
            //public_key: sinkhole_core::PublicKey
        ) -> &[u8];

        /// Decrypts a decodes the result returned by the PIR server.
        fn retrieve(
            result: &[u8],
            //private_key: sinkhole_core::PrivateKey
        ) -> &[u8];
    }
}
