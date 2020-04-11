//! The core traits and types for the `sinkhole` library.

/// This type is a Private Key's byte value.
pub type PrivateKey = Vec<u8>;

/// This type is a Public Key's byte value.
pub type PublicKey = Vec<u8>;

/// A representation of the sinkhole database to query.
///
/// Implementations of this trait contain the
/// servers private data addition and retrieval.
pub trait Storage {
    /// Adds content to the database.
    fn add(&self, content: &[u8]);

    /// Returns the data for a given ID.
    fn retrieve(&self, id: [u8; 32]) -> &[u8];
}
