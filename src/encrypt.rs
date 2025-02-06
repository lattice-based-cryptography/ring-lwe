use polynomial_ring::Polynomial;
use ring_lwe::{Parameters, mod_coeffs, polymul, polyadd, gen_ternary_poly};

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
    let e1 = gen_ternary_poly(n, seed);
    let e2 = gen_ternary_poly(n, seed);
    let u = gen_ternary_poly(n, seed);

    // Compute ciphertext components
    let ct0 = polyadd(&polyadd(&polymul(&pk[0], &u, q*q, f), &e1, q*q, f),&scaled_m,q*q,f);
    let ct1 = polyadd(&polymul(&pk[1], &u, q*q, f), &e2, q*q, f);

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
    
    // Convert each byte into its 8-bit representation (MSB first)
    let message_bits: Vec<i64> = message
        .bytes()
        .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1) as i64))
        .collect();

    // Convert bits into a vector of Polynomials
    let message_blocks: Vec<Polynomial<i64>> = message_bits
        .chunks(params.n)  // Pack bits into polynomials of size `n`
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