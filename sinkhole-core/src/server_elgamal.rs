mod traits;

use errors::errors::ServerError;
use server_elgamal::traits::*;
use std::cell::RefCell;
use rand_core::OsRng;

use curve25519_dalek::scalar::Scalar; 
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use elgamal_ristretto::private::SecretKey;
use elgamal_ristretto::public::PublicKey;
use elgamal_ristretto::ciphertext::Ciphertext;

struct EGServer {
    secretKey: SecretKey,
    size: usize,
    store: RefCell<Vec<Scalar>>,
}

impl EGServer {
    fn new(sk: SecretKey, store: Vec<Scalar>) -> Self {
        return EGServer{
            secretKey: sk,
            size: store.len(),
            store: RefCell::new(store), // mutable interior of Cell
        }
    }

    fn newEmpty(sk: SecretKey, size: usize) -> Self {
        return EGServer{
            secretKey: sk,
            size: size,
            store: RefCell::new(vec![]),
        }
    }
}

impl Storage for EGServer {
    // Adds new content to database state
    fn add(&self, content: Scalar, index: usize) -> Result<(), ServerError> {
        if index > self.size - 1 {
            return Err(ServerError{ error: "Index should not be larger than the size of the storage"
                .to_string()});
        } 

        let mut store = self.store.clone().into_inner();
        store[index] = content; // TODO: how to deal with collisions?
        self.store.replace(store);

        Ok(())
    }

    // Runs encrypted query against the database state
    fn retrieve(&self, query: Vec<Ciphertext>) -> Result<Ciphertext, ServerError> {
        if query.len() != self.size {
            return Err(ServerError{ error: "Query vector should have the same size as the storage"
                .to_string()});
        }
        
        let store = self.store.borrow();
        let mut mult_vector = vec![];
        for (index, content) in store.clone()
            .into_iter()
            .enumerate() {
                let mul = query[index] * content;
                mult_vector.push(mul);
            }
        let mut sum: Ciphertext = mult_vector[0];
        mult_vector.into_iter().map(|x| sum = sum + x);
        
        Ok(sum)
    }
}

/// Generates ElGamal asymmetric key pair for the ristretto curve
fn generate_key_pair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::new(&mut OsRng);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

// TODO: move to client-side
/// Client-side
pub fn generate_query(
    pk: PublicKey, 
    size_query: usize,
    query_index: usize, 
) -> Result<Vec<Ciphertext>, String> {
    if query_index > size_query - 1 {
        return Err("Index of query should not be larger than the size of the query".to_string());
    }
    let mut decrypted_query = vec![Scalar::zero(); size_query - 1];
    decrypted_query.insert(query_index, Scalar::one());

    let query: Vec<Ciphertext> = decrypted_query
        .into_iter()
        .map(|x| pk.encrypt(&(&x * &RISTRETTO_BASEPOINT_TABLE)))
        .collect();

    Ok(query)
}

#[cfg(test)]
mod tests {

    use super::*;
    
    extern crate bincode;
    extern crate rand_core;
    use server_elgamal::tests::rand_core::OsRng;

    #[test]
    fn test_constructor() {
        let size = 4;
        let (sk, _) = generate_key_pair();
        let server = EGServer::newEmpty(sk, size);

        assert!(server.size == size);
    }

    #[test]
    fn testQueryE2E() {
        let mut csprng = OsRng;

        // A) storage setup
        let size = 2;
        let (sk, pk) = generate_key_pair();

        let content_idx_0 = Scalar::random(&mut csprng);
        let content_idx_1 = Scalar::random(&mut csprng);
        let storage = vec![content_idx_0, content_idx_1];

        let server = EGServer::new(sk, storage);

        // B) client-side
        let (client_sk, client_pk) = generate_key_pair();

        let query_idx = 1;
        let query = generate_query(client_pk, 2, query_idx).unwrap(); 

        // C) run query on server-side
        let enc_result = server.retrieve(query).unwrap();

        // D) decrypt result client-side
        let result = client_sk.decrypt(&enc_result);
        
        // E) retrieve Scalar from RistrettoPoint
        //assert!(result == storage[query_idx]);
    }
}
