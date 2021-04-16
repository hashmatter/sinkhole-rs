#![allow(dead_code)]
use sinkhole_core::errors::StorageError;
use sinkhole_core::utils::{
    calculate_vector_boundaries, num_parallel_tasks, zero_ciphertext_from_pk,
};

use rand_core::OsRng;
use std::sync::{Arc, Mutex};
use std::thread;

use curve25519_dalek::scalar::Scalar;
use elgamal_ristretto::ciphertext::Ciphertext;
use elgamal_ristretto::private::SecretKey;
use elgamal_ristretto::public::PublicKey;

#[derive(Debug, Clone)]
pub struct Storage {
    secret_key: SecretKey,
    size: usize,
    store: Vec<Scalar>,
}

impl Storage {
    pub fn new(sk: SecretKey, store: Vec<Scalar>) -> Self {
        Storage {
            secret_key: sk,
            size: store.len(),
            store,
        }
    }

    pub fn new_empty(sk: SecretKey, size: usize) -> Self {
        let mut csprng = OsRng;
        let empty_store: Vec<Scalar> = (1..size).map(|_| Scalar::random(&mut csprng)).collect();

        Storage {
            secret_key: sk,
            size,
            store: empty_store,
        }
    }
}

impl sinkhole_core::traits::core::Storage for Storage {
    fn add(&mut self, content: Scalar, index: usize) -> Result<(), StorageError> {
        if index > self.size - 1 {
            return Err(StorageError {
                error: "Index should not be larger than the size of the storage".to_string(),
            });
        }

        let mut store = self.store.clone();
        store[index] = content; // TODO: how to deal with collisions?
        self.store = store;

        Ok(())
    }

    // Runs encrypted query against the database state
    fn retrieve(&self, query: Vec<Ciphertext>) -> Result<Ciphertext, StorageError> {
        let size = query.len();
        let user_pk = query[0].pk;
        let mut thread_handles = vec![];

        if query.len() != self.size {
            return Err(StorageError {
                error: "Query vector should have the same size as the storage".to_string(),
            });
        }

        // calculates index boundaries to distribute computation in different threads
        let thread_segment_limits = calculate_vector_boundaries(&query, num_parallel_tasks());
        let size_segment = size / thread_segment_limits.len();

        let ciphertext_result = Arc::new(Mutex::new(zero_ciphertext_from_pk(user_pk)));
        let shared_query = Arc::new(Mutex::new(query));
        let shared_store = Arc::new(Mutex::new(self.store.clone())); // TODO: remove this clone

        for segment_i in thread_segment_limits {
            for i in 0..size_segment {
                let ciphertext_result = Arc::clone(&ciphertext_result);
                let shared_query = Arc::clone(&shared_query);
                let shared_store = Arc::clone(&shared_store);

                let handle = thread::spawn(move || {
                    let mut sum = ciphertext_result.lock().unwrap();
                    let query = shared_query.lock().unwrap(); // TODO: remove unwrap
                    let store = shared_store.lock().unwrap(); // TODO: remove unwrap

                    *sum = *sum + (query[segment_i + i] * store[segment_i + i]);
                });

                thread_handles.push(handle);
            }
        }

        for handle in thread_handles {
            handle.join().unwrap(); // TODO: remove unwrap
        }

        let result = *ciphertext_result.lock().unwrap(); // TODO: remove unwrap
        Ok(result)
    }
}

/// Generates ElGamal asymmetric key pair for the ristretto curve
fn generate_key_pair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::new(&mut OsRng);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate bincode;
    extern crate rand_core;

    #[test]
    fn test_constructor() {
        let size = 4;
        let (sk, _) = generate_key_pair();
        let server = Storage::new_empty(sk, size);

        assert!(server.size == size);
    }
}
