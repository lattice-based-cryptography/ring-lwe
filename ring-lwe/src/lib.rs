use polynomial_ring::{Polynomial, polynomial};
use num_traits::pow;
use rand_distr::{Uniform, Normal, Distribution};

pub fn parameters() -> (usize, usize, usize, Polynomial<i64>) {
	// polynomial modulus degree
	let n = pow(2,4);
	// ciphertext modulus
    let q = pow(2,15);
    // plaintext modulus
    let t = pow(2,8);
    // polynomial modulus
	let mut poly_vec = vec![0i64;n+1];
	poly_vec[0] = 1;
	poly_vec[n] = 1;
    let poly_mod = Polynomial::new(poly_vec);
    return (n,q,t,poly_mod)
}

fn mod_coeffs(x : Polynomial<i64>, modulus : i64) -> Polynomial<i64> {
	//Take remainder of the coefficients of a polynom by a given modulus
	//Args:
	//	x: polynom
	//	modulus: coefficient modulus
	//Returns:
	//	polynomial in Z_modulus[X]
	let coeffs = x.coeffs();
	let mut newcoeffs = vec![coeffs[0].rem_euclid(modulus)];
	for i in 1..coeffs.len() {
		newcoeffs.push(coeffs[i].rem_euclid(modulus));
	}
	Polynomial::new(newcoeffs)
}

pub fn polymul(x : Polynomial<i64>, y : Polynomial<i64>, modulus : i64, poly_mod : Polynomial<i64>) -> Polynomial<i64> {
    //Multiply two polynoms
    //Args:
    //	x, y: two polynoms to be multiplied.
    //	modulus: coefficient modulus.
    //	poly_mod: polynomial modulus.
    //Returns:
    //	polynomial in Z_modulus[X]/(poly_mod).
	let mut r = x*y;
	r = mod_coeffs(r, modulus);
	r.division(&poly_mod);
	mod_coeffs(r, modulus)
}

pub fn polyadd(x : Polynomial<i64>, y : Polynomial<i64>, modulus : i64, poly_mod : Polynomial<i64>) -> Polynomial<i64> {
    //Add two polynoms
    //Args:
    //	x, y: two polynoms to be added.
    //	modulus: coefficient modulus.
    //	poly_mod: polynomial modulus.
    //Returns:
    //	polynomial in Z_modulus[X]/(poly_mod).
	let mut r = x+y;
	r = mod_coeffs(r, modulus);
	r.division(&poly_mod);
	mod_coeffs(r, modulus)
}

pub fn polyinv(x : Polynomial<i64>, modulus: i64) -> Polynomial<i64> {
  //Additive inverse of polynomial x modulo modulus
  let mut y = -x;
  mod_coeffs(y, modulus)
}

pub fn polysub(x : Polynomial<i64>, y : Polynomial<i64>, modulus : i64, poly_mod : Polynomial<i64>) -> Polynomial<i64> {
    //Subtract two polynoms
    //Args:
    //	x, y: two polynoms to be added.
    //	modulus: coefficient modulus.
    //	poly_mod: polynomial modulus.
    //Returns:
    //	polynomial in Z_modulus[X]/(poly_mod).
	polyadd(x, polyinv(y, modulus), modulus, poly_mod)
}

pub fn gen_binary_poly(size : usize) -> Polynomial<i64> {
    //Generates a polynomial with coeffecients in [0, 1]
    //Args:
    //	size: number of coeffcients
    //Returns:
    //	polynomial of degree size-1
	let between = Uniform::new(0,2);
	let mut rng = rand::thread_rng();
    let mut coeffs = vec![0i64;size];
	for i in 0..size {
		coeffs[i] = between.sample(&mut rng);
	}
	Polynomial::new(coeffs)
}

pub fn gen_uniform_poly(size: usize, modulus: i64) -> Polynomial<i64> {
    //Generates a polynomial with coeffecients being integers in Z_modulus
    //Args:
    //	size: number of coeffcients
    //Returns:
    //	polynomial of degree size-1
	let between = Uniform::new(0,modulus);
	let mut rng = rand::thread_rng();
    let mut coeffs = vec![0i64;size];
	for i in 0..size {
		coeffs[i] = between.sample(&mut rng);
	}
	Polynomial::new(coeffs)
}

pub fn gen_normal_poly(size: usize) -> Polynomial<i64> {
    //Generates a polynomial with coeffecients in a normal distribution
    //of mean 0 and a standard deviation of 2, then discretize it.
    //Args:
    //	size: number of coeffcients,
    //Returns:
    //	polynomial of degree size-1
	let normal = Normal::new(0.0,2.0).unwrap();
	let mut rng = rand::thread_rng();
    let mut coeffs = vec![0i64;size];
	for i in 0..size {
		coeffs[i] = normal.sample(&mut rng) as i64;
	}
	Polynomial::new(coeffs)
}
