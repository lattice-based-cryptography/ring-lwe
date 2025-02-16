use polynomial_ring::Polynomial;
use rand_distr::{Uniform, Normal, Distribution};
use ntt::{omega,polymul_ntt};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[derive(Debug)]
pub struct Parameters {
    pub n: usize,       // Polynomial modulus degree
    pub q: i64,       // Ciphertext modulus
    pub t: i64,       // Plaintext modulus
    pub omega: i64,   // n-th root of unity
    pub f: Polynomial<i64>, // Polynomial modulus (x^n + 1 representation)
    pub sigma: f64,    // Standard deviation for normal distribution
}

impl Default for Parameters {
    fn default() -> Self {
        let n = 512;
        let q = 12289;
        let t = 2;
        let omega = omega(q, 2*n);
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        let sigma = 8.0;
        Parameters {n, q, t, omega, f, sigma}
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
	let mut c;
	if coeffs.len() == 0 {
		// return original input for the zero polynomial
		x
	} else {
		for i in 0..coeffs.len() {
			c = coeffs[i].rem_euclid(modulus);
			if c > modulus/2 {
				c = c-modulus;
			}
			newcoeffs.push(c);
		}
		Polynomial::new(newcoeffs)
	}
}

pub fn polyrem(x: Polynomial<i64>, f: &Polynomial<i64>) -> Polynomial<i64> {
	//Returns remainder of x modulo f assuming f=x^n+1	
	let n = f.coeffs().len()-1;
	let mut coeffs = x.coeffs().to_vec();
	if coeffs.len() < n+1 {
		return Polynomial::new(coeffs)
	} else{
		for i in n..coeffs.len() {
			coeffs[i % n] = coeffs[i % n]+(-1 as i64).pow((i/n).try_into().unwrap())*coeffs[i];
		}
		coeffs.resize(n,0);
		Polynomial::new(coeffs)
	}
}

pub fn polymul(x : &Polynomial<i64>, y : &Polynomial<i64>, q : i64, f : &Polynomial<i64>) -> Polynomial<i64> {
    //Multiply two polynoms
    //Args:
    //	x, y: two polynoms to be multiplied.
    //	modulus: coefficient modulus.
    //	f: polynomial modulus.
    //Returns:
    //	polynomial in Z_q[X]/(f).
	let mut r = x*y;
    r = polyrem(r,f);
    if q != 0 {
        mod_coeffs(r, q)
    }
    else{
        r
    }
}

pub fn polymul_fast(
    x: &Polynomial<i64>, 
    y: &Polynomial<i64>, 
    q: i64, 
    f: &Polynomial<i64>, 
    omega: i64
) -> Polynomial<i64> {
    // Compute the degree and padded coefficients
    let n = 2 * (x.deg().unwrap() + 1);
    let x_pad = {
        let mut coeffs = x.coeffs().to_vec();
        coeffs.resize(n, 0);
        coeffs
    };
    let y_pad = {
        let mut coeffs = y.coeffs().to_vec();
        coeffs.resize(n, 0);
        coeffs
    };

    // Perform the polynomial multiplication
    let r_coeffs = polymul_ntt(&x_pad, &y_pad, n, q, omega);

    // Construct the result polynomial and reduce modulo f
    let mut r = Polynomial::new(r_coeffs);
    r = polyrem(r,f);
    mod_coeffs(r, q)
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
    r = polyrem(r,f);
    if modulus != 0 {
        mod_coeffs(r, modulus)
    }
    else{
        r
    }
}

pub fn polyinv(x : &Polynomial<i64>, modulus: i64) -> Polynomial<i64> {
    //Additive inverse of polynomial x modulo modulus
    let y = -x;
    if modulus != 0{
      mod_coeffs(y, modulus)
    }
    else {
      y
    }
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

pub fn gen_binary_poly(size : usize, seed: Option<u64>) -> Polynomial<i64> {
    //Generates a polynomial with coeffecients in [0, 1]
    //Args:
    //	size: number of coeffcients
    //Returns:
    //	polynomial of degree size-1
	let between = Uniform::new(0,2);
    let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };
    let mut coeffs = vec![0i64;size];
	for i in 0..size {
		coeffs[i] = between.sample(&mut rng);
	}
	Polynomial::new(coeffs)
}

pub fn gen_ternary_poly(size : usize, seed: Option<u64>) -> Polynomial<i64> {
    //Generates a polynomial with coeffecients in [0, 1]
    //Args:
    //	size: number of coeffcients
    //Returns:
    //	polynomial of degree size-1 with coeffs in {-1,0,+1}
	let between = Uniform::new(-1,2);
    let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };
    let mut coeffs = vec![0i64;size];
	for i in 0..size {
		coeffs[i] = between.sample(&mut rng);
	}
	Polynomial::new(coeffs)
}

pub fn gen_uniform_poly(size: usize, q: i64, seed: Option<u64>) -> Polynomial<i64> {
    //Generates a polynomial with coeffecients being integers in Z_modulus
    //Args:
    //	size: number of coeffcients
    //Returns:
    //	polynomial of degree size-1
	let between = Uniform::new(0,q);
    let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };
    let mut coeffs = vec![0i64;size];
	for i in 0..size {
		coeffs[i] = between.sample(&mut rng);
	}
	mod_coeffs(Polynomial::new(coeffs),q)
}

pub fn gen_normal_poly(size: usize, sigma: f64, seed: Option<u64>) -> Polynomial<i64> {
    //Generates a polynomial with coeffecients in a normal distribution
    //of mean 0 and a standard deviation of 2, then discretize it.
    //Args:
    //	size: number of coeffcients,
    //Returns:
    //	polynomial of degree size-1
	let normal = Normal::new(0.0 as f64, sigma).unwrap();
    let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };
    let mut coeffs = vec![0i64;size];
	for i in 0..size {
		coeffs[i] = normal.sample(&mut rng).round() as i64;
	}
	Polynomial::new(coeffs)
}

//returns the nearest integer to a/b
pub fn nearest_int(a: i64, b: i64) -> i64 {
    if a > 0 {
		(a + b / 2) / b
	}else {
		-((-a + b / 2) / b)
	}
}