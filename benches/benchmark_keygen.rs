use criterion::{criterion_group, criterion_main, Criterion};
use ring_lwe::keygen::{keygen,keygen_string};
use ring_lwe::utils::Parameters;

fn bench_keygen(c: &mut Criterion) {
    let params = Parameters::default();
    c.bench_function("keygen", |b| {
        b.iter(|| keygen(&params, None))
    });
}

fn bench_keygen_string(c: &mut Criterion) {
    let params = Parameters::default();
    
    c.bench_function("keygen_string", |b| {
        b.iter(|| keygen_string(&params, None))
    });
}

criterion_group!(benches, bench_keygen, bench_keygen_string);
criterion_main!(benches);