use polynomial_ring::Polynomial;
use ring_lwe::{mod_coeffs, polymul, polyadd, gen_binary_poly, gen_normal_poly};

pub fn encrypt(
    pk: &[Polynomial<i64>; 2],    // Public key (b, a)
    size: usize,                // Polynomial size
    q: i64,                     // Ciphertext modulus
    t: i64,                     // Plaintext modulus
    poly_mod: &Polynomial<i64>,  // Polynomial modulus
    pt: &Polynomial<i64>,        // Plaintext polynomial
) -> (Polynomial<i64>, Polynomial<i64>) {
    // Scale the plaintext polynomial
    let delta = q / t;
    let scaled_m = mod_coeffs(pt * delta, q);

    // Generate random polynomials
    let e1 = gen_normal_poly(size);
    let e2 = gen_normal_poly(size);
    let u = gen_binary_poly(size);

    // Compute ciphertext components
    let ct0 = polyadd(&polyadd(&polymul(&pk[0], &u, q, poly_mod), &e1, q, poly_mod),&scaled_m,q,poly_mod);
    let ct1 = polyadd(&polymul(&pk[1], &u, q, poly_mod), &e2, q, poly_mod);

    (ct0, ct1)
}
