use polynomial_ring::Polynomial;
use module_lwe::{parameters, add_vec, mul_mat_vec_simple, gen_small_vector, gen_uniform_matrix};
use std::collections::HashMap;

pub fn keygen(
	size: usize, //polynomial modulus degree
	modulus: i64, //ciphertext modulus
	rank: usize, //module rank
	poly_mod: &Polynomial<i64> //polynomial modulus
) -> (Vec<Vec<Polynomial<i64>>>, Vec<Polynomial<i64>>, Vec<Polynomial<i64>>) {
    //Generate a public and secret key
    let a = gen_uniform_matrix(size, rank, modulus);
    let sk = gen_small_vector(size, rank);
    let e = gen_small_vector(size, rank);
    let t = add_vec(&mul_mat_vec_simple(&a, &sk, modulus, &poly_mod), &e, modulus, &poly_mod);
    
    //Return public key (a, t) and secret key (sk) as a 3-tuple
    (a, t, sk)
}

//function to generate public/secret keys as key:value pairs
pub fn keygen_string() -> HashMap<String, String> {

    // Parameters and inputs
    let (n, q, k, f) = parameters();

    //generate public, secret keys
    let (a,t,sk) = keygen(n,q as i64,k,&f);
    let pk = (a,t);

    // Convert public key to a flattened list of coefficients
    let mut pk_coeffs: Vec<i64> = pk.0
        .iter()
        .flat_map(|row| {
            row.iter().flat_map(|poly| {
                let mut coeffs = poly.coeffs().to_vec();
                coeffs.resize(n, 0); // Resize to include leading zeros up to size `n`
                coeffs
            })
        })
        .collect();
    pk_coeffs.extend(
        pk.1.iter()
        .flat_map(|poly| {
            let mut coeffs = poly.coeffs().to_vec();
            coeffs.resize(n, 0); // Resize to include leading zeros up to size `n`
            coeffs
        })
    );

    // Convert secret key to a flattened list of coefficients
    let sk_coeffs: Vec<i64> = sk
        .iter()
        .flat_map(|poly| {
            let mut coeffs = poly.coeffs().to_vec();
            coeffs.resize(n, 0); // Resize to include leading zeros up to size `n`
            coeffs
        })
    .collect();

    // Convert the public/secret key coefficients to a comma-separated string
    let pk_coeffs_str = pk_coeffs.iter()
        .map(|coef| coef.to_string())
        .collect::<Vec<String>>()
        .join(",");
    let sk_coeffs_str = sk_coeffs.iter()
        .map(|coef| coef.to_string())
        .collect::<Vec<String>>()
        .join(",");
    
    //store the secret/public key in a HashMap
    let mut keys: HashMap<String, String> = HashMap::new();
    keys.insert(String::from("secret"), sk_coeffs_str);
    keys.insert(String::from("public"), pk_coeffs_str);
    
    keys
}