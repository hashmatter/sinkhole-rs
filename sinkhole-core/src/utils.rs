pub mod utils {
    use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
    use elgamal_ristretto::ciphertext::Ciphertext;
    use elgamal_ristretto::public::PublicKey;
    use num_cpus;

    pub fn num_parallel_tasks() -> usize {
        return match std::env::var("N_PARALLEL_TASKS") {
            Ok(val) => match val.parse::<usize>() {
                Ok(v) => v,
                Err(_) => num_cpus::get(),
            },
            Err(_) => num_cpus::get(),
        };
    }

    pub fn calculate_vector_boundaries(v: &Vec<Ciphertext>, n_shares: usize) -> Vec<usize> {
        let mut sep_shares: Vec<usize> = vec![];
        let size_shares = v.len() / n_shares;

        let mut i = 0;
        loop {
            sep_shares.push(i);
            i += size_shares;

            if i >= v.len() {
                break;
            }
        }
        sep_shares
    }

    pub fn zero_ciphertext_from_pk(pk: PublicKey) -> Ciphertext {
        Ciphertext {
            pk,
            points: (RistrettoPoint::identity(), RistrettoPoint::identity()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use curve25519_dalek::ristretto::RistrettoPoint;
        use elgamal_ristretto::private::SecretKey;

        #[test]
        fn test_parallel_tasks_set() {
            std::env::set_var("N_PARALLEL_TASKS", 3.to_string());
            assert_eq!(num_parallel_tasks(), 3);
        }

        #[test]
        fn test_parallel_tasks_not_set() {
            assert!(num_parallel_tasks() > 0);
        }

        #[test]
        fn test_boundaries() {
            let v = vec![
                new_ciphertext(),
                new_ciphertext(),
                new_ciphertext(),
                new_ciphertext(),
                new_ciphertext(),
                new_ciphertext(),
                new_ciphertext(),
                new_ciphertext(),
                new_ciphertext(),
                new_ciphertext(),
            ];

            assert_eq!(calculate_vector_boundaries(&v, 2), vec![0, 5]);
            assert_eq!(calculate_vector_boundaries(&v, 3), vec![0, 3, 6, 9]);
            assert_eq!(calculate_vector_boundaries(&v, 5), vec![0, 2, 4, 6, 8]);
        }

        fn new_ciphertext() -> Ciphertext {
            use rand_core::OsRng;

            let mut csprng = OsRng;
            let sk = SecretKey::new(&mut csprng);
            let pk = PublicKey::from(&sk);

            Ciphertext {
                pk,
                points: (
                    RistrettoPoint::random(&mut csprng),
                    RistrettoPoint::random(&mut csprng),
                ),
            }
        }
    }
}
