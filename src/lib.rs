use polynomial_ring::Polynomial;
use rand_distr::{Uniform, Normal, Distribution};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[derive(Debug)]
pub struct Parameters {
    pub n: usize,       // Polynomial modulus degree
    pub q: i64,       // Ciphertext modulus
    pub t: i64,       // Plaintext modulus
    pub f: Polynomial<i64>, // Polynomial modulus (x^n + 1 representation)
    pub sigma: f64,    // Standard deviation for normal distribution
}

impl Default for Parameters {
    fn default() -> Self {
        let n = 512;
        let q = 1048576;
        let t = 256;
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        let sigma = 8.0;
        Parameters { n, q, t, f, sigma}
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
    if modulus != 0 {
        mod_coeffs(r, modulus)
    r.division(f);
    if q != 0 {
        mod_coeffs(r, q)
    }
    else{
        r
    }
}

fn ntt(data: &[i64], _root: i64, _modulus: i64) -> Vec<i64> {
    // Placeholder for Number Theoretic Transform (NTT)
    // This just clones the input for now.
    data.to_vec()
}

fn intt(data: &[i64], _root: i64, _modulus: i64) -> Vec<i64> {
    // Placeholder for Inverse Number Theoretic Transform (INTT)
    // This just clones the input for now.
    data.to_vec()
}


/// Multiplies two polynomials using the Number Theoretic Transform (NTT).
///
/// # Arguments
/// * `a` - Reference to the first polynomial.
/// * `b` - Reference to the second polynomial.
/// * `root` - Primitive root of unity for the NTT.
/// * `modulus` - Modulus under which arithmetic is performed.
///
/// # Returns
/// * A new polynomial representing the product of `a` and `b`.
pub fn ntt_polymul(a: &Polynomial<i64>, b: &Polynomial<i64>, root: i64, modulus: i64) -> Polynomial<i64> {
    // Get the degrees of the polynomials
    let degree_a = a.deg().unwrap_or(0);
    let degree_b = b.deg().unwrap_or(0);

    // Determine the size of the NTT (smallest power of 2 that can hold the result)
    let n = (degree_a + degree_b + 1).next_power_of_two();

    // Extract coefficients and pad them to the required length
    let mut a_padded = a.coeffs().to_vec();
    let mut b_padded = b.coeffs().to_vec();
    a_padded.resize(n, 0);
    b_padded.resize(n, 0);

    // Perform the NTT on both polynomials
    let a_ntt = ntt(&a_padded, root, modulus);
    let b_ntt = ntt(&b_padded, root, modulus);

    // Pointwise multiplication in the NTT domain
    let c_ntt: Vec<i64> = a_ntt
        .iter()
        .zip(&b_ntt)
        .map(|(&x, &y)| (x * y) % modulus)
        .collect();

    // Perform the inverse NTT
    let c_coefficients = intt(&c_ntt, root, modulus);

    // Return the result as a new polynomial
    Polynomial::new(c_coefficients)
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
    (a + b / 2) / b
}