pub mod core {
    extern crate curve25519_dalek;
    extern crate elgamal_ristretto;

    use crate::errors::{QueryError, StorageError};

    // #TODO: may need a higher abstraction representation of a Scalar (result)
    // Ciphertext
    use curve25519_dalek::scalar::Scalar;
    use elgamal_ristretto::ciphertext::Ciphertext;

    /// A representation of the sinkhole database to query.
    ///
    /// Implementations of this trait contain the
    /// servers private data addition and retrieval.
    pub trait Storage {
        /// Adds content to the database.
        fn add(&mut self, content: Scalar, index: usize) -> Result<(), StorageError>;

        /// Returns the data for a given ID.
        fn retrieve(&self, query: Vec<Ciphertext>) -> Result<Ciphertext, StorageError>;
        fn retrieve_parallel(&self, query: Vec<Ciphertext>) -> Result<Ciphertext, StorageError>;
    }

    pub trait Query {
        fn extract_result(&self, result: Ciphertext, k: u32) -> Result<Scalar, QueryError>;
    }
}
