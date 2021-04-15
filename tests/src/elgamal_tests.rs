mod tests {

    use sinkhole_core::traits::core::Query as query_trait;
    use sinkhole_core::traits::core::Storage as storage_trait;
    use sinkhole_elgamal::client::Query;
    use sinkhole_elgamal::storage::Storage;

    use curve25519_dalek::scalar::Scalar;
    use elgamal_ristretto::private::SecretKey;
    use elgamal_ristretto::public::PublicKey;
    use rand_core::OsRng;

    fn generate_key_pair() -> (PublicKey, SecretKey) {
        let sk = SecretKey::new(&mut OsRng);
        let pk = PublicKey::from(&sk);
        (pk, sk)
    }

    #[test]
    fn elgamal_e2e() {
        const K: u32 = 10;
        let size_storage: u32 = 2u32.pow(K);
        let query_index = 100; // content position to retrieve from the storage

        // storage setup
        let (_, storage_sk) = generate_key_pair();
        let mut csprng = OsRng;
        let mut content: Vec<Scalar> = (1..size_storage + 1)
            .map(|_| Scalar::random(&mut csprng))
            .collect();

        content[query_index] = Scalar::from(420u32);

        let storage = Storage::new(storage_sk, content.clone());

        // client setup
        let (_, client_sk) = generate_key_pair();
        let query = Query::new(client_sk, size_storage as usize, query_index);

        assert!(!query.is_err());
        let query = query.unwrap();

        // client queries storage
        let encrypted_result = storage.retrieve(query.clone().encrypted);
        assert!(!encrypted_result.is_err());

        let encrypted_result = encrypted_result.unwrap();
        let result = query.extract_result(encrypted_result, 32);

        assert!(!result.is_err());
        let result = result.unwrap();

        assert_eq!(result, content[query_index]);
    }

    #[test]
    fn elgamal_e2e_parallel() {
        const K: u32 = 10;
        let size_storage: u32 = 2u32.pow(K);
        let query_index = 100; // content position to retrieve from the storage

        // storage setup
        let (_, storage_sk) = generate_key_pair();
        let mut csprng = OsRng;
        let mut content: Vec<Scalar> = (1..size_storage + 1)
            .map(|_| Scalar::random(&mut csprng))
            .collect();

        content[query_index] = Scalar::from(420u32);

        let storage = Storage::new(storage_sk, content.clone());

        // client setup
        let (_, client_sk) = generate_key_pair();
        let query = Query::new(client_sk, size_storage as usize, query_index);

        assert!(!query.is_err());
        let query = query.unwrap();

        // client queries storage
        let encrypted_result = storage.retrieve_parallel(query.clone().encrypted);
        assert!(!encrypted_result.is_err());

        let encrypted_result = encrypted_result.unwrap();
        let result = query.extract_result(encrypted_result, 32);

        assert!(!result.is_err());
        let result = result.unwrap();

        assert_eq!(result, content[query_index]);
    }
}
