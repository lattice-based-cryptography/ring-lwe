use polynomial_ring::Polynomial;
use ring_lwe::{Parameters, polymul, polyadd, gen_binary_poly, gen_uniform_poly, gen_normal_poly};
use std::collections::HashMap;

pub fn keygen(n: usize, modulus: i64, f: &Polynomial<i64>) -> ([Polynomial<i64>; 2], Polynomial<i64>) {
    // Generate a public and secret key
    let sk = gen_binary_poly(n);
    let a = gen_uniform_poly(n, modulus);
    let e = gen_normal_poly(n);
    let b = polyadd(&polymul(&-&a, &sk, modulus, &f), &-&e, modulus, &f);
    
    // Return public key (b, a) as an array and secret key (sk)
    ([b, a], sk)
}

pub fn keygen_string(params: &Parameters) -> HashMap<String,String> {

    // generate keys using parameters
    let (pk, sk) = keygen(params.n, params.q , &params.f);

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