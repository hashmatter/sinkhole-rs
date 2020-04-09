//! The core traits and types for the `sinkhole` library.

/// A representation of the sinkhole database to query.
///
/// Implementations of this trait contain the
/// servers private data addition and retrieval.
pub trait Storage {
    /// Adds content to the database.
    fn add(&self, content: [u8]);

    /// Returns the data for a given ID.
    fn retrieve(&self, id: [u8; 32]) -> [u8];
}

