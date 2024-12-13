use polynomial_ring::Polynomial;
use rand_distr::{Uniform, Distribution};
pub mod ring_mod;
use ring_mod::{polyadd, polymul, gen_uniform_poly};

#[derive(Debug)]
pub struct Parameters {
    pub n: usize,       // Polynomial modulus degree
    pub q: usize,       // Ciphertext modulus
    pub k: usize,       // Plaintext modulus
    pub f: Polynomial<i64>, // Polynomial modulus (x^n + 1 representation)
}

impl Default for Parameters {
    fn default() -> Self {
        let n = 4;
        let q = 67;
        let k = 2;
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        Parameters { n, q, k, f }
    }
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
	//take the transpose of a matrix of polynomials
	
	let mut result = vec![vec![Polynomial::new(vec![]); m.len()]; m[0].len()];
	for i in 0..m.len() {
		for j in 0..m[0].len() {
			result[j][i] = m[i][j].clone();
		}
	}
	result
}

pub fn gen_small_vector(size : usize, rank: usize) -> Vec<Polynomial<i64>> {
	//generates a vector of given rank of degree size-1 polynomials
	//with coefficients in [-1,0,1]
	
	let mut v = vec![];
	let between = Uniform::new(0,3);
    let mut rng = rand::thread_rng();
    let mut coeffs = vec![0i64;size];
	for _i in 0..rank {
		for j in 0.. size {
			coeffs[j] = between.sample(&mut rng)-1;
		}
		v.push(Polynomial::new(coeffs.clone()));
	}
	v
}

pub fn gen_uniform_matrix(size : usize, rank: usize, modulus: i64) -> Vec<Vec<Polynomial<i64>>> {
	//generates a rank by rank matrix of degree size-1 polynomials
	//with uniform coefficients in Z_modulus
	
	let mut m = vec![vec![Polynomial::new(vec![]); rank]; rank];
	for i in 0..rank {
		for j in 0..rank {
			m[i][j] = gen_uniform_poly(size, modulus);
		}
	}
	m
}
	