use std::time::Instant;
use ring_lwe::{polymul, polymul_fast, Parameters, gen_uniform_poly};
use polynomial_ring::Polynomial;

fn main() {
    benchmark_polymul_small();
    benchmark_polymul_uniform();
}

fn benchmark_polymul_small() {
    let p: i64 = 17; // Prime modulus
    let root: i64 = 3; // Primitive root of unity for the modulus
    let params = Parameters::default();

    // Input polynomials (padded to length `n`)
    let a = Polynomial::new(vec![1, 2, 3, 4]);
    let b = Polynomial::new(vec![5, 6, 7, 8]);

    // Time standard multiplication
    let start_std = Instant::now();
    let c_std = polymul(&a, &b, p, &params.f);
    let duration_std = start_std.elapsed();
    println!("Standard multiplication (small) took: {:?}", duration_std);

    // Time fast multiplication
    let start_fast = Instant::now();
    let c_fast = polymul_fast(&a, &b, p, &params.f, root);
    let duration_fast = start_fast.elapsed();
    println!("Fast multiplication (small) took: {:?}", duration_fast);

    // Verify correctness
    assert_eq!(c_std, c_fast, "Benchmark failed: {} != {}", c_std, c_fast);
}

fn benchmark_polymul_uniform() {
    let seed = None; // Set the random seed
    let p: i64 = 12289; // Prime modulus
    let root: i64 = 11; // Primitive root of unity for the modulus
    let params = Parameters::default();

    // Input polynomials (padded to length `n`)
    let a = gen_uniform_poly(params.n, p, seed);
    let b = gen_uniform_poly(params.n, p, seed);

    // Time standard multiplication
    let start_std = Instant::now();
    let c_std = polymul(&a, &b, p, &params.f);
    let duration_std = start_std.elapsed();
    println!("Standard multiplication (large) took: {:?}", duration_std);

    // Time fast multiplication
    let start_fast = Instant::now();
    let c_fast = polymul_fast(&a, &b, p, &params.f, root);
    let duration_fast = start_fast.elapsed();
    println!("Fast multiplication (large) took: {:?}", duration_fast);

    // Verify correctness
    assert_eq!(c_std, c_fast, "Benchmark failed: {} != {}", c_std, c_fast);
}

