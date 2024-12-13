use polynomial_ring::Polynomial;
use ring_lwe::{parameters, polymul, polyadd};

pub fn decrypt(
    sk: &Polynomial<i64>,    // Secret key
    size: usize,                // Polynomial size
    q: i64,                     // Ciphertext modulus
    t: i64,                     // Plaintext modulus
    poly_mod: &Polynomial<i64>,  // Polynomial modulus
    ct: &[Polynomial<i64>; 2],        // Array of ciphertext polynomials
) -> Polynomial<i64> {
	let scaled_pt = polyadd(&polymul(&ct[1], sk, q, poly_mod),&ct[0], q, poly_mod);
	let mut decrypted_coeffs = vec![];
	let mut s;
	for i in 0..size {
		s = (scaled_pt.coeffs()[i] as f64) * (t as f64) / (q as f64);
		decrypted_coeffs.push(s.round() as i64 % t);
	}
    Polynomial::new(decrypted_coeffs)
}

pub fn decrypt_string(sk_string: &String, ciphertext_string: &String) -> String {

    // Encryption scheme parameters
    let (n, q, t, poly_mod) = parameters();

    //get the secret key and format as polynomial
    let sk_coeffs: Vec<i64> = sk_string
        .split(',')
        .filter_map(|x| x.parse::<i64>().ok())
        .collect();
    let sk = Polynomial::new(sk_coeffs);

    // Get the ciphertext to be decrypted
    let ciphertext_array: Vec<i64> = ciphertext_string
    .split(',')
    .map(|s| s.parse::<i64>().unwrap())
    .collect();

    let num_bytes = ciphertext_array.len() / (2 * n);
    let mut decrypted_message = String::new();

    for i in 0..num_bytes {
        let c0 = Polynomial::new(ciphertext_array[2 * i * n..(2 * i + 1) * n].to_vec());
        let c1 = Polynomial::new(ciphertext_array[(2 * i + 1) * n..(2 * i + 2) * n].to_vec());
        let ct = [c0, c1];

        // Decrypt the ciphertext
        let decrypted_poly = decrypt(&sk, n, q.try_into().unwrap(), t.try_into().unwrap(), &poly_mod, &ct);

        // Convert the coefficients to characters and append to the message
        decrypted_message.push_str(
            &decrypted_poly
                .coeffs()
                .iter()
                .map(|&coeff| coeff as u8 as char)
                .collect::<String>(),
        );
    }

    decrypted_message
}