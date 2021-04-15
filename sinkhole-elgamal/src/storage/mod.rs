#![allow(dead_code)]
use sinkhole_core::errors::StorageError;

use rand_core::OsRng;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
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
            store: store,
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
        if query.len() != self.size {
            return Err(StorageError {
                error: "Query vector should have the same size as the storage".to_string(),
            });
        }

        let store = self.store.clone();
        let mut mult_vector = vec![];
        for (index, content) in store.clone().into_iter().enumerate() {
            let mul = query[index] * content;
            mult_vector.push(mul);
        }

        let mut sum: Ciphertext = mult_vector[0];
        for cipher in mult_vector {
            sum = sum + cipher;
        }

        Ok(sum)
    }

    // Runs encrypted query against the database state in paralell
    fn retrieve_parallel(&self, query: Vec<Ciphertext>) -> Result<Ciphertext, StorageError> {
        let size = query.len();

        if query.len() != self.size {
            return Err(StorageError {
                error: "Query vector should have the same size as the storage".to_string(),
            });
        }

        let user_pk = query[0].pk;

        let mut handles = vec![];

        // todo: refactor
        let mut zero_ciphertext = Ciphertext {
            points: (RistrettoPoint::identity(), RistrettoPoint::identity()),
            pk: user_pk,
        };
        zero_ciphertext.points = (RistrettoPoint::identity(), RistrettoPoint::identity());

        let ciphertext_result = Arc::new(Mutex::new(zero_ciphertext));
        let shared_query = Arc::new(Mutex::new(query));
        let shared_store = Arc::new(Mutex::new(self.store.clone())); // TODO: remove this clone

        for segment_i in 0..2 {
            for i in 0..size / 2 {
                let start_index = segment_i * size / 2;

                let ciphertext_result = Arc::clone(&ciphertext_result);
                let shared_query = Arc::clone(&shared_query);
                let shared_store = Arc::clone(&shared_store);

                let handle = thread::spawn(move || {
                    let mut sum = ciphertext_result.lock().unwrap();
                    let query = shared_query.lock().unwrap();
                    let store = shared_store.lock().unwrap();

                    *sum = *sum + (query[start_index + i] * store[start_index + i]);
                });

                handles.push(handle);
            }
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let result = *ciphertext_result.lock().unwrap();
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
