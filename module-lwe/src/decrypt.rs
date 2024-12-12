use polynomial_ring::Polynomial;
use module_lwe::mul_vec_simple;
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
	println!("{:?}", scaled_pt.coeffs());
	let half_q = q/2+1;
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