extern crate curve25519_dalek;
extern crate elgamal_ristretto;

use errors::errors::ServerError;
use elgamal_ristretto::ciphertext::Ciphertext;
use curve25519_dalek::scalar::Scalar; 

/// A representation of the sinkhole database to query.
///
/// Implementations of this trait contain the
/// servers private data addition and retrieval.
pub trait Storage {
    /// Adds content to the database.
    fn add(&self, content: Scalar, index: usize) -> Result<(), ServerError>;

    /// Returns the data for a given ID.
    fn retrieve(&self, query: Vec<Ciphertext>) -> Result<Ciphertext, ServerError>;
}
