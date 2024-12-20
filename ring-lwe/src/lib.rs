use polynomial_ring::Polynomial;
use rand_distr::{Uniform, Normal, Distribution};

#[derive(Debug)]
pub struct Parameters {
    pub n: usize,       // Polynomial modulus degree
    pub q: i64,       // Ciphertext modulus
    pub t: i64,       // Plaintext modulus
    pub f: Polynomial<i64>, // Polynomial modulus (x^n + 1 representation)
}

impl Default for Parameters {
    fn default() -> Self {
        let n = 32;
        let q = 4_194_304;
        let t = 256;
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        Parameters { n, q, t, f }
    }
}

pub fn mod_coeffs(x : Polynomial<i64>, modulus : i64) -> Polynomial<i64> {
	//Take remainder of the coefficients of a polynom by a given modulus
	//Args:
	//	x: polynom
	//	modulus: coefficient modulus
	//Returns:
	//	polynomial in Z_modulus[X]
	let coeffs = x.coeffs();
	let mut newcoeffs = vec![];
	if coeffs.len() == 0 {
		// return original input for the zero polynomial
		x
	} else {
		for i in 0..coeffs.len() {
			newcoeffs.push(coeffs[i].rem_euclid(modulus));
		}
		Polynomial::new(newcoeffs)
	}
}

pub fn polymul(x : &Polynomial<i64>, y : &Polynomial<i64>, modulus : i64, f : &Polynomial<i64>) -> Polynomial<i64> {
    //Multiply two polynoms
    //Args:
    //	x, y: two polynoms to be multiplied.
    //	modulus: coefficient modulus.
    //	f: polynomial modulus.
    //Returns:
    //	polynomial in Z_modulus[X]/(f).
	let mut r = x*y;
	r = mod_coeffs(r, modulus);
	r.division(f);
	mod_coeffs(r, modulus)
}

pub fn polyadd(x : &Polynomial<i64>, y : &Polynomial<i64>, modulus : i64, f : &Polynomial<i64>) -> Polynomial<i64> {
    //Add two polynoms
    //Args:
    //	x, y: two polynoms to be added.
    //	modulus: coefficient modulus.
    //	f: polynomial modulus.
    //Returns:
    //	polynomial in Z_modulus[X]/(f).
	let mut r = x+y;
	r = mod_coeffs(r, modulus);
	r.division(f);
	mod_coeffs(r, modulus)
}

pub fn polyinv(x : &Polynomial<i64>, modulus: i64) -> Polynomial<i64> {
  //Additive inverse of polynomial x modulo modulus
  let y = -x;
  mod_coeffs(y, modulus)
}

pub fn polysub(x : &Polynomial<i64>, y : &Polynomial<i64>, modulus : i64, f : Polynomial<i64>) -> Polynomial<i64> {
    //Subtract two polynoms
    //Args:
    //	x, y: two polynoms to be added.
    //	modulus: coefficient modulus.
    //	f: polynomial modulus.
    //Returns:
    //	polynomial in Z_modulus[X]/(f).
	polyadd(x, &polyinv(y, modulus), modulus, &f)
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
	let normal = Normal::new(0.0 as f64, 2.0 as f64).unwrap();
	let mut rng = rand::thread_rng();
    let mut coeffs = vec![0i64;size];
	for i in 0..size {
		coeffs[i] = normal.sample(&mut rng).round() as i64;
	}
	Polynomial::new(coeffs)
}

pub fn nearest_int(a: i64, b: i64) -> i64 {
    //Returns the nearest integer to a/b
    //Args: i64 a, i64 b
    //Returns: i64 \lfloor a/b + 0.5 \rfloor

    (a as f64 / b as f64).round() as i64

}