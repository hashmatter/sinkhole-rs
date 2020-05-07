#[derive(Debug)]
pub struct StorageError {
    pub error: String,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cause: {}", self.error)
    }
}

#[derive(Debug)]
pub struct QueryError {
    pub error: String,
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cause: {}", self.error)
    }
}
