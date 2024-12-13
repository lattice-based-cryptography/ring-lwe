use polynomial_ring::Polynomial;
use ring_lwe::{parameters, polymul, polyadd, gen_binary_poly, gen_uniform_poly, gen_normal_poly};
use std::collections::HashMap;

pub fn keygen(size: usize, modulus: i64, poly_mod: &Polynomial<i64>) -> ([Polynomial<i64>; 2], Polynomial<i64>) {
    // Generate a public and secret key
    let sk = gen_binary_poly(size);
    let a = gen_uniform_poly(size, modulus);
    let e = gen_normal_poly(size);
    let b = polyadd(&polymul(&-&a, &sk, modulus, &poly_mod), &-&e, modulus, &poly_mod);
    
    // Return public key (b, a) as an array and secret key (sk)
    ([b, a], sk)
}

pub fn keygen_string() -> HashMap<String,String> {
    // Encryption scheme parameters
    let (n, q, _t, poly_mod) = parameters();

    // Keygen: Convert n and q from usize to i64
    let (pk, sk) = keygen(n, q.try_into().unwrap(), &poly_mod);

    let mut pk_coeffs: Vec<i64> = Vec::with_capacity(2*n);
    pk_coeffs.extend(pk[0].coeffs());
    pk_coeffs.extend(pk[1].coeffs());

    // Convert the public key coefficients to a comma-separated string
    let pk_coeffs_str = pk_coeffs.iter()
            .map(|coef| coef.to_string())
            .collect::<Vec<String>>()
            .join(",");
    
    // Convert the secret key coefficients to a comma-separated string
    let sk_coeffs_str = sk.coeffs().iter()
            .map(|coef| coef.to_string())
            .collect::<Vec<String>>()
            .join(",");
    
    //store public/secret keys in HashMap
    let mut keys: HashMap<String, String> = HashMap::new();
    keys.insert(String::from("secret"), sk_coeffs_str);
    keys.insert(String::from("public"), pk_coeffs_str);
    keys
}