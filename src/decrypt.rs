use polynomial_ring::Polynomial;
use ring_lwe::{Parameters, polymul_fast, polyadd, nearest_int};

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

pub fn decrypt_string(sk_string: &String, ciphertext_string: &String, params: &Parameters) -> String {
    // Get the secret key and format as polynomial
    let sk_coeffs: Vec<i64> = sk_string
        .split(',')
        .filter_map(|x| x.parse::<i64>().ok())
        .collect();
    let sk = Polynomial::new(sk_coeffs);

    // Get the ciphertext to be decrypted
    let ciphertext_array: Vec<i64> = ciphertext_string
        .split(',')
        .filter_map(|s| s.parse::<i64>().ok())
        .collect();

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
