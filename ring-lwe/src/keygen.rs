use polynomial_ring::Polynomial;
use ring_lwe::{polymul, polyadd, gen_binary_poly, gen_uniform_poly, gen_normal_poly};

pub fn keygen(size: usize, modulus: i64, poly_mod: &Polynomial<i64>) -> ([Polynomial<i64>; 2], Polynomial<i64>) {
    // Generate a public and secret key
    let sk = gen_binary_poly(size);
    let a = gen_uniform_poly(size, modulus);
    let e = gen_normal_poly(size);
    let b = polyadd(polymul(-a.clone(), sk.clone(), modulus, &poly_mod), -e, modulus, &poly_mod);
    
    // Return public key (b, a) as an array and secret key (sk)
    ([b, a], sk)
}