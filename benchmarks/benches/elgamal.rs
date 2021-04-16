use criterion::{criterion_group, criterion_main, Criterion};

use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

use elgamal_ristretto::{private::SecretKey, public::PublicKey};
use sinkhole_core::traits::core::Storage as storage_trait;
use sinkhole_elgamal::client::Query;
use sinkhole_elgamal::storage::Storage;

pub fn keypair_benchmark(c: &mut Criterion) {
    c.bench_function("Generate key pair", |b| {
        b.iter(|| {
            let sk = SecretKey::new(&mut OsRng);
            let _ = PublicKey::from(&sk);
        })
    });
}

pub fn query_generation_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_gen_group");
    group.sample_size(10);

    let sk = SecretKey::new(&mut OsRng);

    group.bench_function("Generate query size 2^5", |b| {
        b.iter(|| {
            let _ = Query::new(sk.clone(), 2usize.pow(5), 10);
        })
    });

    group.bench_function("Generate query size 2^10", |b| {
        b.iter(|| {
            let _ = Query::new(sk.clone(), 2usize.pow(10), 10);
        })
    });

    group.bench_function("Generate query size 2^15", |b| {
        b.iter(|| {
            let _ = Query::new(sk.clone(), 2usize.pow(15), 10);
        })
    });

    group.bench_function("Generate query size 2^20", |b| {
        b.iter(|| {
            let _ = Query::new(sk.clone(), 2usize.pow(20), 10);
        })
    });
}

pub fn db_setup_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("db_setup_group");
    let mut csprng = OsRng;

    let sk = SecretKey::new(&mut OsRng);

    group.bench_function("Setup DB size 2^5", |b| {
        b.iter(|| {
            let content: Vec<Scalar> = (1..2usize.pow(5) + 1)
                .map(|_| Scalar::random(&mut csprng))
                .collect();

            let _ = Storage::new(sk.clone(), content.clone());
        })
    });

    group.bench_function("Setup DB size 2^10", |b| {
        b.iter(|| {
            let content: Vec<Scalar> = (1..2usize.pow(10) + 1)
                .map(|_| Scalar::random(&mut csprng))
                .collect();

            let _ = Storage::new(sk.clone(), content.clone());
        })
    });

    group.bench_function("Setup DB size 2^15", |b| {
        b.iter(|| {
            let content: Vec<Scalar> = (1..2usize.pow(15) + 1)
                .map(|_| Scalar::random(&mut csprng))
                .collect();

            let _ = Storage::new(sk.clone(), content.clone());
        })
    });

    group.bench_function("Setup DB size 2^20", |b| {
        b.iter(|| {
            let content: Vec<Scalar> = (1..2usize.pow(20) + 1)
                .map(|_| Scalar::random(&mut csprng))
                .collect();

            let _ = Storage::new(sk.clone(), content.clone());
        })
    });
}

pub fn run_query_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("run_query_group");
    group.sample_size(10);

    fn setup(
        size: usize,
    ) -> (
        sinkhole_elgamal::storage::Storage,
        sinkhole_elgamal::client::Query,
    ) {
        let mut csprng = OsRng;

        let storage_sk = SecretKey::new(&mut OsRng);
        let client_sk = SecretKey::new(&mut OsRng);

        let content: Vec<Scalar> = (1..size + 1).map(|_| Scalar::random(&mut csprng)).collect();
        let storage = Storage::new(storage_sk.clone(), content.clone());
        let query = Query::new(client_sk.clone(), size, 10).unwrap();

        (storage, query)
    }

    let (storage_2pow5, query_2pow5) = setup(2usize.pow(5));
    let (storage_2pow10, query_2pow10) = setup(2usize.pow(10));
    let (storage_2pow15, query_2pow15) = setup(2usize.pow(15));
    let (storage_2pow20, query_2pow20) = setup(2usize.pow(20));

    group.bench_function("Run query size 2^5", |b| {
        b.iter(|| {
            let _ = storage_2pow5.retrieve(query_2pow5.clone().encrypted);
        })
    });

    group.bench_function("Run query size 2^10", |b| {
        b.iter(|| {
            let _ = storage_2pow10.retrieve(query_2pow10.clone().encrypted);
        })
    });

    group.bench_function("Run query size 2^15", |b| {
        b.iter(|| {
            let _ = storage_2pow15.retrieve(query_2pow15.clone().encrypted);
        })
    });

    group.bench_function("Run query size 2^20", |b| {
        b.iter(|| {
            let _ = storage_2pow20.retrieve(query_2pow20.clone().encrypted);
        })
    });
}

pub fn one_threaded_retrieve_test(c: &mut Criterion) {
    let mut group = c.benchmark_group("run_query_group");
    group.sample_size(10);

    // only one thread
    std::env::set_var("N_PARALLEL_TASKS", 1.to_string());

    fn setup(
        size: usize,
    ) -> (
        sinkhole_elgamal::storage::Storage,
        sinkhole_elgamal::client::Query,
    ) {
        let mut csprng = OsRng;

        let storage_sk = SecretKey::new(&mut OsRng);
        let client_sk = SecretKey::new(&mut OsRng);

        let content: Vec<Scalar> = (1..size + 1).map(|_| Scalar::random(&mut csprng)).collect();
        let storage = Storage::new(storage_sk.clone(), content.clone());
        let query = Query::new(client_sk.clone(), size, 10).unwrap();

        (storage, query)
    }

    let (storage_2pow15, query_2pow15) = setup(2usize.pow(15));

    group.bench_function("Run query size 2^15", |b| {
        b.iter(|| {
            let _ = storage_2pow15.retrieve(query_2pow15.clone().encrypted);
        })
    });
}

pub fn parallel_retrieve_test(c: &mut Criterion) {
    let mut group = c.benchmark_group("run_query_group");
    group.sample_size(10);

    // run in 4 threads
    std::env::set_var("N_PARALLEL_TASKS", 4.to_string());

    fn setup(
        size: usize,
    ) -> (
        sinkhole_elgamal::storage::Storage,
        sinkhole_elgamal::client::Query,
    ) {
        let mut csprng = OsRng;

        let storage_sk = SecretKey::new(&mut OsRng);
        let client_sk = SecretKey::new(&mut OsRng);

        let content: Vec<Scalar> = (1..size + 1).map(|_| Scalar::random(&mut csprng)).collect();
        let storage = Storage::new(storage_sk.clone(), content.clone());
        let query = Query::new(client_sk.clone(), size, 10).unwrap();

        (storage, query)
    }

    let (storage_2pow15, query_2pow15) = setup(2usize.pow(15));

    group.bench_function("Run query size 2^15", |b| {
        b.iter(|| {
            let _ = storage_2pow15.retrieve(query_2pow15.clone().encrypted);
        })
    });
}

criterion_group!(
    benches,
    keypair_benchmark,
    query_generation_benchmark,
    db_setup_benchmark,
    run_query_benchmark,
    parallel_retrieve_test,
    one_threaded_retrieve_test,
);
criterion_main!(benches);
