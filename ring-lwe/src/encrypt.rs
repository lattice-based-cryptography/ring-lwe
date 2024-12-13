use polynomial_ring::Polynomial;
use ring_lwe::{Parameters, mod_coeffs, polymul, polyadd, gen_binary_poly, gen_normal_poly};

pub fn encrypt(
    pk: &[Polynomial<i64>; 2],    // Public key (b, a)
    size: usize,                // Polynomial size
    q: i64,                     // Ciphertext modulus
    t: i64,                     // Plaintext modulus
    poly_mod: &Polynomial<i64>,  // Polynomial modulus
    pt: &Polynomial<i64>,        // Plaintext polynomial
) -> (Polynomial<i64>, Polynomial<i64>) {
    // Scale the plaintext polynomial
    let delta = q / t;
    let scaled_m = mod_coeffs(pt * delta, q);

    // Generate random polynomials
    let e1 = gen_normal_poly(size);
    let e2 = gen_normal_poly(size);
    let u = gen_binary_poly(size);

    // Compute ciphertext components
    let ct0 = polyadd(&polyadd(&polymul(&pk[0], &u, q, poly_mod), &e1, q, poly_mod),&scaled_m,q,poly_mod);
    let ct1 = polyadd(&polymul(&pk[1], &u, q, poly_mod), &e2, q, poly_mod);

    (ct0, ct1)
}

pub fn encrypt_string(pk_string: &String, message: &String, params: &Parameters) -> String {

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
        let ciphertext = encrypt(&pk, params.n, params.q as i64, params.t as i64, &params.poly_mod, &message_block);
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