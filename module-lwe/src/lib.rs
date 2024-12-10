use polynomial_ring::Polynomial;
use num_traits::pow;
use rand_distr::{Uniform, Normal, Distribution};
mod ring_mod;
use ring_mod::{polymul, polyadd};

pub fn parameters() -> (usize, usize, usize, Polynomial<i64>) {
	// polynomial modulus degree
	let n = pow(2,2);
	// ciphertext modulus
    let q = 67;
    // module rank
    let k = 2;
    // polynomial modulus x^n+1
	let mut poly_vec = vec![0i64;n+1];
	poly_vec[0] = 1;
	poly_vec[n] = 1;
    let poly_mod = Polynomial::new(poly_vec);
    return (n,q,k,poly_mod)
}

pub fn add_vec(v0: &Vec<Polynomial<i64>>, v1: &Vec<Polynomial<i64>>, modulus: i64, poly_mod: &Polynomial<i64>) -> Vec<Polynomial<i64>> {
	//add two vectors of polynomials
	
	assert!(v0.len() == v1.len());
	// sizes need to be the same
	
	let mut result = vec![];
	for i in 0..v0.len() {
		result.push(polyadd(&v0[i], &v1[i], modulus, &poly_mod));
	}
	result
}

pub fn mul_vec_simple(v0: &Vec<Polynomial<i64>>, v1: &Vec<Polynomial<i64>>, modulus: i64, poly_mod: &Polynomial<i64>) -> Polynomial<i64> {
	//take the dot product of two vectors of polynomials
	
	assert!(v0.len() == v1.len());
	// sizes need to be the same
	
	let mut result = Polynomial::new(vec![]);
	for i in 0..v0.len() {
		result = polyadd(&result, &polymul(&v0[i], &v1[i], modulus, &poly_mod), modulus, &poly_mod);
	}
	result
}

pub fn mul_mat_vec_simple(m: &Vec<Vec<Polynomial<i64>>>, v: &Vec<Polynomial<i64>>, modulus: i64, poly_mod: &Polynomial<i64>) -> Vec<Polynomial<i64>> {
	//multiply a matrix by a vector of polynomials
	
	let mut result = vec![];
	for i in 0..m.len() {
		result.push(mul_vec_simple(&m[i], &v, modulus, &poly_mod));
	}
	result
}

pub fn transpose(m: &Vec<Vec<Polynomial<i64>>>) -> Vec<Vec<Polynomial<i64>>> {
	let mut result = vec![vec![Polynomial::new(vec![]); m.len()]; m[0].len()];
	for i in 0..m.len() {
		for j in 0..m[0].len() {
			result[j][i] = m[i][j].clone();
		}
	}
	result
}