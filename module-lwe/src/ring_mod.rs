use polynomial_ring::Polynomial;
use rand_distr::{Uniform, Distribution};
use rand::SeedableRng;
use rand::rngs::StdRng;

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
		x
	} else {
		for i in 0..coeffs.len() {
			newcoeffs.push(coeffs[i].rem_euclid(modulus));
		}
		Polynomial::new(newcoeffs)
	}
}

pub fn polymul(x : &Polynomial<i64>, y : &Polynomial<i64>, modulus : i64, poly_mod : &Polynomial<i64>) -> Polynomial<i64> {
    //Multiply two polynoms
    //Args:
    //	x, y: two polynoms to be multiplied.
    //	modulus: coefficient modulus.
    //	poly_mod: polynomial modulus.
    //Returns:
    //	polynomial in Z_modulus[X]/(poly_mod).
	let mut r = x*y;
	r = mod_coeffs(r, modulus);
	r.division(poly_mod);
	mod_coeffs(r, modulus)
}

pub fn polyadd(x : &Polynomial<i64>, y : &Polynomial<i64>, modulus : i64, poly_mod : &Polynomial<i64>) -> Polynomial<i64> {
    //Add two polynoms
    //Args:
    //	x, y: two polynoms to be added.
    //	modulus: coefficient modulus.
    //	poly_mod: polynomial modulus.
    //Returns:
    //	polynomial in Z_modulus[X]/(poly_mod).
	let mut r = x+y;
	r = mod_coeffs(r, modulus);
	r.division(poly_mod);
	mod_coeffs(r, modulus)
}

pub fn polyinv(x : &Polynomial<i64>, modulus: i64) -> Polynomial<i64> {
  //Additive inverse of polynomial x modulo modulus
  let y = -x;
  mod_coeffs(y, modulus)
}

pub fn polysub(x : &Polynomial<i64>, y : &Polynomial<i64>, modulus : i64, poly_mod : &Polynomial<i64>) -> Polynomial<i64> {
    //Subtract two polynoms
    //Args:
    //	x, y: two polynoms to be added.
    //	modulus: coefficient modulus.
    //	poly_mod: polynomial modulus.
    //Returns:
    //	polynomial in Z_modulus[X]/(poly_mod).
	polyadd(x, &polyinv(y, modulus), modulus, poly_mod)
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
	Polynomial::new(coeffs)
}