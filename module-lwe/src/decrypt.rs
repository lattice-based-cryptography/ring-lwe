use polynomial_ring::Polynomial;
use module_lwe::{Parameters,mul_vec_simple};
use module_lwe::ring_mod::polysub;

pub fn decrypt(
    sk: &Vec<Polynomial<i64>>,    //secret key
    q: i64,                     //ciphertext modulus
    poly_mod: &Polynomial<i64>,  //polynomial modulus
    u: &Vec<Polynomial<i64>>, //ciphertext vector
	v: &Polynomial<i64> 		//ciphertext polynomial
) -> Vec<i64> {
	//Decrypt a ciphertext (u,v)
	//Returns a plaintext vector
	
	//Compute v-sk*u mod q
	let scaled_pt = polysub(&v, &mul_vec_simple(&sk, &u, q, &poly_mod), q, &poly_mod);
	let half_q = (q as f64 / 2.0 + 0.5) as i64;
	let mut decrypted_coeffs = vec![];
	let mut s;
	for c in scaled_pt.coeffs().iter() {
		if (half_q-c).abs() < std::cmp::min(*c, (q-c).abs()) {
			s = 1;
		} else {
			s = 0;
		};
		decrypted_coeffs.push(s);
	}
    decrypted_coeffs
}

//decrypt a ciphertext string given a secret key
pub fn decrypt_string(sk_string: &String, ciphertext_string: &String, params: &Parameters) -> String {

    //get parameters
    let (n, q, k, f) = (params.n, params.q, params.k, &params.f);
    
    // Convert the secret key string into a Vec<Polynomial<i64>>
    let sk_array: Vec<i64> = sk_string.split(',')
        .filter_map(|s| s.parse().ok())
        .collect();
    let sk: Vec<Polynomial<i64>> = sk_array.chunks(n)
        .map(|chunk| Polynomial::new(chunk.to_vec()))
        .collect();
    
    // Parse ciphertext into u and v
    let ciphertext_list: Vec<i64> = ciphertext_string.split(',')
        .filter_map(|s| s.parse().ok())
        .collect();
    let block_size = (k + 1) * n;
    let num_blocks = ciphertext_list.len() / block_size;

    let mut message_binary = vec![];
    
    for i in 0..num_blocks {
        // Get u and v for this block
        let u_array = &ciphertext_list[i * block_size..i * block_size + k * n];
        let v_array = &ciphertext_list[i * block_size + k * n..(i + 1) * block_size];
            
        let u: Vec<Polynomial<i64>> = u_array.chunks(n)
            .map(|chunk| Polynomial::new(chunk.to_vec()))
            .collect();
        let v = Polynomial::new(v_array.to_vec());
            
        // Decrypt the ciphertext
        let mut m_b = decrypt(&sk, q as i64, &f, &u, &v);
        m_b.resize(n,0);
            
        message_binary.extend(m_b);
    }
    
    // Group the bits back into bytes (8 bits each)
    let byte_chunks: Vec<String> = message_binary.chunks(8)
        .map(|chunk| chunk.iter().map(|bit| bit.to_string()).collect())
        .collect();
        
    // Convert each binary string back into a character
    let message_string: String = byte_chunks.iter()
        .map(|byte| char::from_u32(i64::from_str_radix(byte, 2).unwrap() as u32).unwrap())
        .collect();
    
    //trim the null characters \0 = '00000000' from the end
    message_string.trim_end_matches('\0').to_string()
}