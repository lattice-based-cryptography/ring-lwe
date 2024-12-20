use polynomial_ring::Polynomial;
use ring_lwe::{Parameters, mod_coeffs, polymul, polyadd, gen_binary_poly, gen_normal_poly};

pub fn encrypt(
    pk: &[Polynomial<i64>; 2],    // Public key (b, a)
    m: &Polynomial<i64>,        // Plaintext polynomial
    params: &Parameters,       //parameters (n,q,t,f)
    seed: Option<u64>            // Seed for random number generator
) -> (Polynomial<i64>, Polynomial<i64>) {
    let (n,q,t,f) = (params.n, params.q, params.t, &params.f);
    // Scale the plaintext polynomial. use floor(m*q/t) rather than floor (q/t)*m
    let scaled_m = mod_coeffs(m * q / t, q);

    // Generate random polynomials
    let e1 = gen_normal_poly(n, seed);
    let e2 = gen_normal_poly(n, seed);
    let u = gen_binary_poly(n, seed);

    // Compute ciphertext components
    let ct0 = polyadd(&polyadd(&polymul(&pk[0], &u, q, f), &e1, q, f),&scaled_m,q,f);
    let ct1 = polyadd(&polymul(&pk[1], &u, q, f), &e2, q, f);

    (ct0, ct1)
}

pub fn encrypt_string(pk_string: &String, message: &String, params: &Parameters, seed: Option<u64>) -> String {

    // Get the public key from the string and format as two Polynomials
    let pk_arr: Vec<i64> = pk_string
        .split(',')
        .filter_map(|x| x.parse::<i64>().ok())
        .collect();

    let pk_b = Polynomial::new(pk_arr[..params.n].to_vec());
    let pk_a = Polynomial::new(pk_arr[params.n..].to_vec());
    let pk = [pk_b, pk_a];

    // Define the integers to be encrypted
    
    let message_bytes: Vec<String> = message
        .bytes()
        .map(|byte| format!("{:b}", byte))
        .collect();

    let message_ints: Vec<i64> = message_bytes
        .iter()
        .filter_map(|byte| i64::from_str_radix(byte, 2).ok())
        .collect();

    // Convert message integers into a vector of Polynomials
    let message_blocks: Vec<Polynomial<i64>> = message_ints
        .chunks(params.n)
        .map(|chunk| Polynomial::new(chunk.to_vec()))
        .collect();

    // Encrypt each integer message block
    let mut ciphertext_list: Vec<i64> = Vec::new();
    for message_block in message_blocks {
        let ciphertext = encrypt(&pk, &message_block, &params, seed);
        ciphertext_list.extend(ciphertext.0.coeffs());
        ciphertext_list.extend(ciphertext.1.coeffs());
    }

    // Format the ciphertext list as a comma-separated string
    let ciphertext_string = ciphertext_list
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(",");
    ciphertext_string
}