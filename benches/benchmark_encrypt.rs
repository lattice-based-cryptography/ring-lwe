use criterion::{criterion_group, criterion_main, Criterion};
use ring_lwe::encrypt::{encrypt,encrypt_string};
use ring_lwe::keygen::{keygen,keygen_string};
use ring_lwe::utils::Parameters;
use polynomial_ring::Polynomial;

fn bench_encrypt(c: &mut Criterion) {
    let params = Parameters::default();
    let (pk, _) = keygen(&params, None);
    let m_b = Polynomial::new(vec![0, 1, 0, 1, 1, 0, 1, 0]); // Example binary message

    c.bench_function("encrypt", |b| {
        b.iter(|| encrypt(&pk, &m_b, &params, None))
    });
}

fn bench_encrypt_string(c: &mut Criterion) {
    let params = Parameters::default();
    let keypair = keygen_string(&params, None);
    let pk_string = keypair.get("public").unwrap();
    let message = String::from("hello");

    c.bench_function("encrypt_string", |b| {
        b.iter(|| encrypt_string(&pk_string, &message, &params, None))
    });
}

criterion_group!(benches, bench_encrypt, bench_encrypt_string);
criterion_main!(benches);