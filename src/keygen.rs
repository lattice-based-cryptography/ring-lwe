use crate::utils::{Parameters, polymul_fast, polyadd, polyinv, gen_ternary_poly, gen_uniform_poly};
use polynomial_ring::Polynomial;
use std::collections::HashMap;
use base64::{engine::general_purpose, Engine as _};

/// Generate a public and secret key pair
/// # Arguments:
///	* `params` - ring-LWE parameters
/// * `seed` - random seed
/// # Returns:
///	(public key, secret key)
/// # Example:
/// ```
/// let params = ring_lwe::utils::Parameters::default();
/// let (pk, sk) = ring_lwe::keygen::keygen(&params, None);
/// ```
pub fn keygen(params: &Parameters, seed: Option<u64>) -> ([Polynomial<i64>; 2], Polynomial<i64>) {

    //rename parameters
    let (n, q, f, omega) = (params.n, params.q, &params.f, params.omega);

    // Generate a public and secret key
    let sk = gen_ternary_poly(n, seed);
    let a = gen_uniform_poly(n, q, seed);
    let e = gen_ternary_poly(n, seed);
    let b = polyadd(&polymul_fast(&polyinv(&a,q), &sk, q, &f, omega), &polyinv(&e,q), q, &f); // b = -a*sk - e
    
    // Return public key (b, a) as an array and secret key (sk)
    ([b, a], sk)
}

/// Generate a public and secret key pair and return as a HashMap
/// # Arguments:
///	* `params` - ring-LWE parameters
/// * `seed` - random seed
/// # Returns:
///	HashMap containing public and secret keys
/// # Example:
/// ```
/// let params = ring_lwe::utils::Parameters::default();
/// let keys = ring_lwe::keygen::keygen_string(&params, None);
/// let pk_string = keys.get("public").unwrap();
/// let sk_string = keys.get("secret").unwrap();
/// ```
pub fn keygen_string(params: &Parameters, seed: Option<u64>) -> HashMap<String, String> {
    // Generate keys using parameters
    let (pk, sk) = keygen(params, seed);

    let mut pk_coeffs: Vec<i64> = Vec::with_capacity(2 * params.n);
    pk_coeffs.extend(pk[0].coeffs());
    pk_coeffs.extend(pk[1].coeffs());

    // Serialize the coefficients as binary data
    let pk_bytes = bincode::serialize(&pk_coeffs).expect("Failed to serialize public key");
    let sk_bytes = bincode::serialize(&sk.coeffs()).expect("Failed to serialize secret key");

    // Encode the binary data to Base64
    let pk_base64 = general_purpose::STANDARD.encode(&pk_bytes);
    let sk_base64 = general_purpose::STANDARD.encode(&sk_bytes);

    // Store public/secret keys in a HashMap
    let mut keys: HashMap<String, String> = HashMap::new();
    keys.insert(String::from("secret"), sk_base64);
    keys.insert(String::from("public"), pk_base64);
    keys
}