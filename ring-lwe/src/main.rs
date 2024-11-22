use polynomial_ring::Polynomial;
use serde_json::json;
use ring_lwe::{parameters, polymul, polyadd, gen_binary_poly, gen_uniform_poly, gen_normal_poly};

fn keygen(size: usize, modulus: i64, poly_mod: Polynomial<i64>) -> ([Polynomial<i64>; 2], Polynomial<i64>) {
    // Generate a public and secret key
    let sk = gen_binary_poly(size);
    let a = gen_uniform_poly(size, modulus);
    let e = gen_normal_poly(size);
    let b = polyadd(polymul(-a.clone(), sk.clone(), modulus, poly_mod.clone()), -e, modulus, poly_mod);
    
    // Return public key (b, a) as an array and secret key (sk)
    ([b, a], sk)  // Using an array instead of a Vec
}


fn main() {
    // Encryption scheme parameters
    let (n, q, _t, poly_mod) = parameters();

    // Keygen: Convert n and q from usize to i64
    let (pk, sk) = keygen(n, q.try_into().unwrap(), poly_mod);
    
    // Convert keys to vector of integers
    let keys = json!({
        "secret": sk.coeffs(),
        "public_b": pk[0].coeffs(),
        "public_a": pk[1].coeffs()
    });

    // Print keys in JSON format
    println!("{}", serde_json::to_string(&keys).unwrap());
}

