use polynomial_ring::Polynomial;
use rand_distr::{Uniform, Normal, Distribution};
use ntt::polymul_ntt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use base64::{engine::general_purpose, Engine as _};
use bincode;

/// Ring-LWE parameters
#[derive(Debug)]
pub struct Parameters {
    pub n: usize,       // Polynomial modulus degree
    pub q: i64,       // Ciphertext modulus
    pub t: i64,       // Plaintext modulus
    pub omega: i64,   // n-th root of unity mod q
    pub f: Polynomial<i64>, // Polynomial modulus (x^n + 1 representation)
    #[allow(dead_code)]
    pub sigma: f64,    // Standard deviation for normal distribution
}

/// Default parameters for ring-LWE
impl Default for Parameters {
    fn default() -> Self {
        let n = 1024;
        let q = 12289;
        let t = 2;
        let omega = ntt::omega(q, 2*n);
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        let sigma = 8.0;
        Parameters {n, q, t, omega, f, sigma}
    }
}

/// Take remainder of the coefficients of a polynom by a given modulus
/// # Arguments:
/// * `x` - polynomial in Z[X]
///	* `modulus` - coefficient modulus
/// # Returns:
/// polynomial in Z_modulus[X]
pub fn mod_coeffs(x : Polynomial<i64>, modulus : i64) -> Polynomial<i64> {

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

/// Polynomial emainder of x modulo f assuming f=x^n+1
/// # Arguments:
/// * `x` - polynomial in Z[X]
///	* `f` - polynomial modulus
/// # Returns:
/// polynomial in Z[X]/(f)
pub fn polyrem(x: Polynomial<i64>, f: &Polynomial<i64>) -> Polynomial<i64> {
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

/// Multiply two polynomials
/// # Arguments:
///	* `x` - polynomial to be multiplied
/// * `y` - polynomial to be multiplied.
/// * `modulus` - coefficient modulus.
///	* `f` - polynomial modulus.
/// # Returns:
///	polynomial in Z_q[X]/(f)
#[allow(dead_code)]
pub fn polymul(x : &Polynomial<i64>, y : &Polynomial<i64>, q : i64, f : &Polynomial<i64>) -> Polynomial<i64> {
	let mut r = x*y;
    r = polyrem(r,f);
    if q != 0 {
        mod_coeffs(r, q)
    }
    else{
        r
    }
}

/// Multiply two polynomials using fast NTT algorithm
/// # Arguments:
///	* `x` - polynomial to be multiplied
/// * `y` - polynomial to be multiplied.
/// * `q` - coefficient modulus.
///	* `f` - polynomial modulus.
/// * `omega` - n-th root of unity
/// # Returns:
///	polynomial in Z_q[X]/(f)
/// # Example:
/// ```
/// let p: i64 = 17; // Prime modulus
/// let n: usize = 8;  // Length of the NTT (must be a power of 2)
/// let omega = ntt::omega(p, n); // n-th root of unity
/// let params = ring_lwe::utils::Parameters::default();
/// let a = polynomial_ring::Polynomial::new(vec![1, 2, 3, 4]);
/// let b = polynomial_ring::Polynomial::new(vec![5, 6, 7, 8]);
/// let c_std = ring_lwe::utils::polymul(&a, &b, p, &params.f);
/// let c_fast = ring_lwe::utils::polymul_fast(&a, &b, p, &params.f, omega);
/// assert_eq!(c_std, c_fast, "test failed: {} != {}", c_std, c_fast);
/// ```
pub fn polymul_fast(
    x: &Polynomial<i64>, 
    y: &Polynomial<i64>, 
    q: i64, 
    f: &Polynomial<i64>, 
    omega: i64
) -> Polynomial<i64> {
    let n1 = x.coeffs().len();
    let n2 = y.coeffs().len();
    // Compute the nearest power of 2 at least twice the max of input degrees+1
    let n = 2*(std::cmp::max(n1, n2)).next_power_of_two();
    // Pad coefficients
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


/// Add two polynomials
/// # Arguments:
///	* `x` - polynomial to be added
/// * `y` - polynomial to be added.
/// * `modulus` - coefficient modulus.
///	* `f` - polynomial modulus.
/// # Returns:
///	polynomial in Z_modulus[X]/(f)
pub fn polyadd(x : &Polynomial<i64>, y : &Polynomial<i64>, modulus : i64, f : &Polynomial<i64>) -> Polynomial<i64> {
	let mut r = x+y;
    r = polyrem(r,f);
    if modulus != 0 {
        mod_coeffs(r, modulus)
    }
    else{
        r
    }
}

/// Additive inverse of a polynomial
/// # Arguments:
///	* `x` - polynomial to be inverted
/// * `modulus` - coefficient modulus.
/// # Returns:
///	polynomial in Z_modulus[X]
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

/// Subtract two polynomials
/// # Arguments:
///	* `x` - polynomial to be subtracted
/// * `y` - polynomial to be subtracted.
/// * `modulus` - coefficient modulus.
///	* `f` - polynomial modulus.
/// # Returns:
///	polynomial in Z_modulus[X]/(f)
#[allow(dead_code)]
pub fn polysub(x : &Polynomial<i64>, y : &Polynomial<i64>, modulus : i64, f : &Polynomial<i64>) -> Polynomial<i64> {
	polyadd(x, &polyinv(y, modulus), modulus, f)
}

/// Generate a binary polynomial
/// # Arguments:
///	* `size` - number of coefficients
/// * `seed` - random seed
/// # Returns:
///	polynomial in Z_modulus[X]/(f) with coefficients in {0,1}
#[allow(dead_code)]
pub fn gen_binary_poly(size : usize, seed: Option<u64>) -> Polynomial<i64> {
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

/// Generate a ternary polynomial
/// # Arguments:
///	* `size` - number of coefficients
/// * `seed` - random seed
/// # Returns:
///	ternary polynomial with coefficients in {-1,0,+1}
pub fn gen_ternary_poly(size : usize, seed: Option<u64>) -> Polynomial<i64> {
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

/// Generate a uniform polynomial
/// # Arguments:
///	* `size` - number of coefficients
/// * `q` - coefficient modulus
/// * `seed` - random seed
/// # Returns:
///	uniform polynomial with coefficients in {0,1,...,q-1}
pub fn gen_uniform_poly(size: usize, q: i64, seed: Option<u64>) -> Polynomial<i64> {
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

/// Generate a normal polynomial
/// # Arguments:
///	* `size` - number of coefficients
/// * `sigma` - standard deviation
/// * `seed` - random seed
/// # Returns:
///	polynomial with coefficients sampled from a normal distribution
#[allow(dead_code)]
pub fn gen_normal_poly(size: usize, sigma: f64, seed: Option<u64>) -> Polynomial<i64> {
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

/// nearest integer to the ratio a/b
/// # Arguments:
///	* `a` - numerator
/// * `b` - denominator
/// # Returns:
///	nearest integer to the ratio a/b
pub fn nearest_int(a: i64, b: i64) -> i64 {
    if a > 0 {
		(a + b / 2) / b
	}else {
		-((-a + b / 2) / b)
	}
}

/// seralize and encode a vector of i64 to a base64 encoded string
/// # Arguments
/// * `data` - vector of i64
/// # Returns
/// * `encoded` - base64 encoded string
pub fn compress(data: &Vec<i64>) -> String {
    let serialized_data = bincode::serialize(data).expect("Failed to serialize data");
    general_purpose::STANDARD.encode(&serialized_data)
}

/// decode and deserialize a base64 encoded string to a vector of i64
/// # Arguments
/// * `base64_str` - base64 encoded string
/// # Returns
/// * `decoded_data` - vector of i64
pub fn decompress(base64_str: &str) -> Vec<i64> {
    let decoded_bytes = general_purpose::STANDARD.decode(base64_str).expect("Failed to decode base64 string");
    bincode::deserialize(&decoded_bytes).expect("Failed to deserialize data")
}