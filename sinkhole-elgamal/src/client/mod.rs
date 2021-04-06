#![allow(dead_code)]

use sinkhole_core::errors::QueryError;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use elgamal_ristretto::ciphertext::Ciphertext;
use elgamal_ristretto::private::SecretKey;
use elgamal_ristretto::public::PublicKey;

#[derive(Debug, Clone)]
pub struct Query {
    pub encrypted: Vec<Ciphertext>,
    private_key: SecretKey,
    size: usize,
}

impl Query {
    pub fn new(sk: SecretKey, size: usize, index: usize) -> Result<Self, QueryError> {
        if index > size - 1 {
            return Err(QueryError {
                error: "Index of query should not be larger than the size of the query".to_owned(),
            });
        }

        let pk = PublicKey::from(&sk);
        let mut decrypted_query = vec![Scalar::zero(); size - 1];
        decrypted_query.insert(index, Scalar::one());

        let encrypted_query: Vec<Ciphertext> = decrypted_query
            .into_iter()
            .map(|x| pk.encrypt(&(&x * &RISTRETTO_BASEPOINT_TABLE)))
            .collect();

        Ok(Query {
            private_key: sk,
            size,
            encrypted: encrypted_query,
        })
    }
}

impl sinkhole_core::traits::core::Query for Query {
    fn extract_result(&self, result: Ciphertext, k: u32) -> Result<Scalar, QueryError> {
        let point_result = self.private_key.decrypt(&result);
        recover_scalar(point_result, k)
    }
}

fn recover_scalar(
    point: curve25519_dalek::ristretto::RistrettoPoint,
    k: u32,
) -> Result<Scalar, QueryError> {
    for i in 0..2u64.pow(k) {
        if &Scalar::from(i as u64) * &RISTRETTO_BASEPOINT_TABLE == point {
            return Ok(Scalar::from(i as u64));
        }
    }
    Err(QueryError {
        error: format!["Scalar is not within the [0..2^{}] range", k],
    })
}
