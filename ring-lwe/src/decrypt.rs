use polynomial_ring::Polynomial;
use ring_lwe::{polymul, polyadd};

pub fn decrypt(
    sk: Polynomial<i64>,    // Secret key
    size: usize,                // Polynomial size
    q: i64,                     // Ciphertext modulus
    t: i64,                     // Plaintext modulus
    poly_mod: &Polynomial<i64>,  // Polynomial modulus
    ct: [Polynomial<i64>; 2],        // Array of ciphertext polynomials
) -> Polynomial<i64> {
	let scaled_pt = polyadd(polymul(ct[1].clone(), sk, q, poly_mod),ct[0].clone(), q, poly_mod);
	let mut decrypted_coeffs = vec![];
	let mut s;
	for i in 0..size {
		s = scaled_pt.coeffs()[i] as f64 * t as f64 / q as f64;
		decrypted_coeffs.push(s.round() as i64 % t);
	}
    Polynomial::new(decrypted_coeffs)
}