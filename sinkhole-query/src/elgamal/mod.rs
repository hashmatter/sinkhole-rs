#![allow(dead_code)]

use errors::errors::QueryError;

use elgamal_ristretto::ciphertext::Ciphertext;
use elgamal_ristretto::public::PublicKey;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

#[derive(Debug, Clone)]
pub struct Query {
    pub encrypted: Vec<Ciphertext>,
    public_key: PublicKey,
    size: usize,
}

impl Query {
    pub fn new(pk: PublicKey, size: usize, index: usize) -> Result<Self, QueryError> {
        if index > size - 1 {
            return Err(QueryError {
                error: "Index of query should not be larger than the size of the query".to_owned(),
            });
        }
        let mut decrypted_query = vec![Scalar::zero(); size - 1];
        decrypted_query.insert(index, Scalar::one());

        let encrypted_query: Vec<Ciphertext> = decrypted_query
            .into_iter()
            .map(|x| pk.encrypt(&(&x * &RISTRETTO_BASEPOINT_TABLE)))
            .collect();

        Ok(Query {
            public_key: pk,
            size: size,
            encrypted: encrypted_query,
        })
    }
}

pub fn recover_scalar(
    point: curve25519_dalek::ristretto::RistrettoPoint,
    k: u32,
) -> Result<Scalar, QueryError> {
    for i in 0..2u64.pow(k) {
        if &Scalar::from(i as u64) * &RISTRETTO_BASEPOINT_TABLE == point {
            return Ok(Scalar::from(i as u64));
        }
    }
    Err(QueryError {
        error: format!["Scalar is not in [0..2^{}] range", k],
    })
}
