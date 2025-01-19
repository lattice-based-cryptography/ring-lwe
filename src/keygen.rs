use polynomial_ring::Polynomial;
use ring_lwe::{Parameters, polymul, polyadd, polyinv, gen_ternary_poly, gen_uniform_poly};
use std::collections::HashMap;

pub fn keygen(params: &Parameters, seed: Option<u64>) -> ([Polynomial<i64>; 2], Polynomial<i64>) {

    //rename parameters
    let (n, q, f) = (params.n, params.q, &params.f);

    // Generate a public and secret key
    let sk = gen_ternary_poly(n, seed);
    let a = gen_uniform_poly(n, q, seed);
    let e = gen_ternary_poly(n, seed);
    let b = polyadd(&polymul(&polyinv(&a,q*q), &sk, q*q, &f), &polyinv(&e,q*q), q*q, &f);
    
    // Return public key (b, a) as an array and secret key (sk)
    ([b, a], sk)
}

pub fn keygen_string(params: &Parameters, seed: Option<u64>) -> HashMap<String,String> {

    // generate keys using parameters
    let (pk, sk) = keygen(params,seed);

    let mut pk_coeffs: Vec<i64> = Vec::with_capacity(2*params.n);
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