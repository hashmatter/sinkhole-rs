use criterion::{criterion_group, criterion_main, Criterion};

use elgamal_ristretto::{private::SecretKey, public::PublicKey};
use rand_core::OsRng;

pub fn criterion_benchmark(c: &mut Criterion) {
        c.bench_function("generate key pair", |b| {
            b.iter(|| {
                let sk = SecretKey::new(&mut OsRng);
                let _ = PublicKey::from(&sk);
            })
        });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
