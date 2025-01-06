use polynomial_ring::Polynomial;
use ring_lwe::{Parameters, polymul, polyadd, nearest_int};

pub fn decrypt(
    sk: &Polynomial<i64>,    // Secret key
    ct: &[Polynomial<i64>; 2],        // Array of ciphertext polynomials
    params: &Parameters
) -> Polynomial<i64> {
    let (_n,q,t,f) = (params.n, params.q, params.t, &params.f);
	let scaled_pt = polyadd(&polymul(&ct[1], sk, q, f),&ct[0], q, f);
	let mut decrypted_coeffs = vec![];
	let mut s;
	for c in scaled_pt.coeffs().iter() {
		s = nearest_int(c*t,q) % t;
		decrypted_coeffs.push(s);
	}
    Polynomial::new(decrypted_coeffs)
}

pub fn decrypt_string(sk_string: &String, ciphertext_string: &String, params: &Parameters) -> String {

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

    let num_bytes = ciphertext_array.len() / (2 * params.n);
    let mut decrypted_message = String::new();

    for i in 0..num_bytes {
        let c0 = Polynomial::new(ciphertext_array[2 * i * params.n..(2 * i + 1) * params.n].to_vec());
        let c1 = Polynomial::new(ciphertext_array[(2 * i + 1) * params.n..(2 * i + 2) * params.n].to_vec());
        let ct = [c0, c1];

        // Decrypt the ciphertext
        let decrypted_poly = decrypt(&sk, &ct, &params);

        // Convert the coefficients to characters and append to the message
        decrypted_message.push_str(
            &decrypted_poly
                .coeffs()
                .iter()
                .map(|&coeff| coeff as u8 as char)
                .collect::<String>(),
        );
    }

    decrypted_message.trim_end_matches('\0').to_string()
}