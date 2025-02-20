use crate::utils::{Parameters, polymul_fast, polyadd, nearest_int};
use polynomial_ring::Polynomial;
use base64::{engine::general_purpose, Engine as _};
use bincode;

/// Decrypt a ciphertext using the secret key
/// # Arguments:
/// * `sk` - secret key
/// * `ct` - array of ciphertext polynomials
/// * `params` - ring-LWE parameters
/// # Returns:
///	decrypted polynomial
/// # Example:
/// ```
/// let params = ring_lwe::utils::Parameters::default();
/// let (pk, sk) = ring_lwe::keygen::keygen(&params, None);
/// let m = polynomial_ring::Polynomial::new(vec![1, 0, 1]);
/// let ct = ring_lwe::encrypt::encrypt(&pk, &m, &params, None);
/// let decrypted_m = ring_lwe::decrypt::decrypt(&sk, &ct, &params);
/// ```
pub fn decrypt(
    sk: &Polynomial<i64>,    // Secret key
    ct: &[Polynomial<i64>; 2],        // Array of ciphertext polynomials
    params: &Parameters
) -> Polynomial<i64> {
    let (_n,q,t,f,omega) = (params.n, params.q, params.t, &params.f, params.omega);
	let scaled_pt = polyadd(&polymul_fast(&ct[1], sk, q, f, omega),&ct[0], q, f);
	let mut decrypted_coeffs = vec![];
	let mut s;
	for c in scaled_pt.coeffs().iter() {
		s = nearest_int(c*t,q);
		decrypted_coeffs.push(s.rem_euclid(t));
	}
    Polynomial::new(decrypted_coeffs)
}

/// Decrypt a ciphertext string using the secret key
/// # Arguments:
/// * `sk_string` - secret key as a base64 encoded string
/// * `ciphertext_string` - ciphertext to decrypt as a base64 encoded string
/// * `params` - ring-LWE parameters
/// # Returns:
///	decrypted plaintext message
/// # Example:
/// ```
/// let params = ring_lwe::utils::Parameters::default();
/// let keys = ring_lwe::keygen::keygen_string(&params, None);
/// let sk_string = keys.get("secret").unwrap();
/// let pk_string = keys.get("public").unwrap();
/// let message = String::from("hello");
/// let ciphertext_string = ring_lwe::encrypt::encrypt_string(pk_string, &message, &params, None);
/// let decrypted_message = ring_lwe::decrypt::decrypt_string(sk_string, &ciphertext_string, &params);
/// ```
pub fn decrypt_string(sk_base64: &String, ciphertext_base64: &String, params: &Parameters) -> String {
    // Decode the Base64 secret key string
    let sk_bytes = general_purpose::STANDARD.decode(sk_base64)
        .expect("Failed to decode Base64 secret key");

    // Deserialize the binary data into a vector of i64 coefficients
    let sk_coeffs: Vec<i64> = bincode::deserialize(&sk_bytes)
        .expect("Failed to deserialize secret key");

    // Reconstruct the secret key polynomial
    let sk = Polynomial::new(sk_coeffs);

    // Decode the Base64 ciphertext string
    let ciphertext_bytes = general_purpose::STANDARD.decode(ciphertext_base64)
        .expect("Failed to decode Base64 ciphertext");

    // Deserialize the binary ciphertext into a vector of i64 coefficients
    let ciphertext_array: Vec<i64> = bincode::deserialize(&ciphertext_bytes)
        .expect("Failed to deserialize ciphertext");

    let num_blocks = ciphertext_array.len() / (2 * params.n);
    let mut decrypted_bits: Vec<i64> = Vec::new();

    for i in 0..num_blocks {
        let c0 = Polynomial::new(ciphertext_array[2 * i * params.n..(2 * i + 1) * params.n].to_vec());
        let c1 = Polynomial::new(ciphertext_array[(2 * i + 1) * params.n..(2 * i + 2) * params.n].to_vec());
        let ct = [c0, c1];

        // Decrypt the ciphertext
        decrypted_bits.extend(decrypt(&sk, &ct, &params).coeffs());
    }

    // Convert decrypted bits into a string
    let decrypted_message: String = decrypted_bits
        .chunks(8)
        .map(|byte| {
            let bit_str: String = byte.iter().map(|&b| (b as u8 + b'0') as char).collect();
            u8::from_str_radix(&bit_str, 2).unwrap_or(0) as char
        })
        .collect();

    decrypted_message.trim_end_matches('\0').to_string()
}
