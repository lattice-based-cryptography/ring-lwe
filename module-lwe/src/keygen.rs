use polynomial_ring::Polynomial;
use module_lwe::{add_vec, mul_mat_vec_simple, gen_small_vector, gen_uniform_matrix};

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
    
    //Return public key (A, t) and secret key (sk) as a 3-tuple
    (a, t, sk)
}