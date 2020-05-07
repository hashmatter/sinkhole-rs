#![allow(dead_code)]
use sinkhole_core::errors::errors::StorageError;

use rand_core::OsRng;
use std::cell::RefCell;

use curve25519_dalek::scalar::Scalar;
use elgamal_ristretto::ciphertext::Ciphertext;
use elgamal_ristretto::private::SecretKey;
use elgamal_ristretto::public::PublicKey;

#[derive(Debug, Clone)]
pub struct Storage {
    secret_key: SecretKey,
    size: usize,
    store: RefCell<Vec<Scalar>>,
}

impl Storage {
    pub fn new(sk: SecretKey, store: Vec<Scalar>) -> Self {
        return Storage {
            secret_key: sk,
            size: store.len(),
            store: RefCell::new(store),
        };
    }

    pub fn new_empty(sk: SecretKey, size: usize) -> Self {
        let mut csprng = OsRng;
        let empty_store: Vec<Scalar> = (1..size).map(|_| Scalar::random(&mut csprng)).collect();

        return Storage {
            secret_key: sk,
            size: size,
            store: RefCell::new(empty_store),
        };
    }
}

impl sinkhole_core::traits::core::Storage for Storage {
    fn add(&self, content: Scalar, index: usize) -> Result<(), StorageError> {
        if index > self.size - 1 {
            return Err(StorageError {
                error: "Index should not be larger than the size of the storage".to_string(),
            });
        }

        let mut store = self.store.clone().into_inner();
        store[index] = content; // TODO: how to deal with collisions?
        self.store.replace(store);

        Ok(())
    }

    // Runs encrypted query against the database state
    fn retrieve(&self, query: Vec<Ciphertext>) -> Result<Ciphertext, StorageError> {
        if query.len() != self.size {
            return Err(StorageError {
                error: "Query vector should have the same size as the storage".to_string(),
            });
        }

        let store = self.store.borrow();
        let mut mult_vector = vec![];
        for (index, content) in store.clone().into_iter().enumerate() {
            let mul = query[index] * content;
            mult_vector.push(mul);
        }

        let mut sum: Ciphertext = mult_vector[0] - mult_vector[0];
        for cipher in mult_vector {
            sum = sum + cipher;
        }

        Ok(sum)
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
