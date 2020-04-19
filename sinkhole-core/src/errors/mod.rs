pub mod errors {
    #[derive(Debug)]
    pub struct ServerError {
        pub error: String
    }

    impl std::fmt::Display for ServerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Cause: {}", self.error)
        }
    }
}
