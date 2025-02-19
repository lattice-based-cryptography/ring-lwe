use criterion::{criterion_group, criterion_main, Criterion};
use ring_lwe::utils::{polymul, polymul_fast, Parameters, gen_uniform_poly};
use ntt::omega;
use polynomial_ring::Polynomial;

fn benchmark_polymul_small(c: &mut Criterion) {
    let p: i64 = 17; // Prime modulus
    let n: usize = 8;  // Length of the NTT (must be a power of 2)
    let omega = omega(p, n); // n-th root of unity
    let params = Parameters::default();

    // Input polynomials (padded to length `n`)
    let poly_0 = Polynomial::new(vec![1, 2, 3, 4]);
    let poly_1 = Polynomial::new(vec![5, 6, 7, 8]);

    // Time standard multiplication
    c.bench_function("Standard polymul (small)", |b| {
        b.iter(|| polymul(&poly_0, &poly_1, p, &params.f))
    });

    // Time fast multiplication
    c.bench_function("Fast polymul (small)", |b| {
        b.iter(|| polymul_fast(&poly_0, &poly_1, p, &params.f, omega))
    });
}

fn benchmark_polymul_uniform(c: &mut Criterion) {
    let seed = None; // Set the random seed
    let params = Parameters::default();
    let (n, q, omega) = (params.n, params.q, params.omega);

    // Input polynomials (padded to length `n`)
    let poly_0 = gen_uniform_poly(n, q, seed);
    let poly_1 = gen_uniform_poly(n, q, seed);

    // Time standard multiplication
    c.bench_function("Standard polymul (large)", |b| {
        b.iter(|| polymul(&poly_0, &poly_1, q, &params.f))
    });

    // Time fast multiplication
    c.bench_function("Fast polymul (large)", |b| {
        b.iter(|| polymul_fast(&poly_0, &poly_1, q, &params.f, omega))
    });
}

criterion_group!(benches, benchmark_polymul_small, benchmark_polymul_uniform);
criterion_main!(benches);