use polynomial_ring::Polynomial;
use serde_json::json;
use ring_lwe::{parameters, polymul, polyadd, gen_binary_poly, gen_uniform_poly, gen_normal_poly};

fn keygen(size: usize, modulus: i64, poly_mod: Polynomial<i64>) -> ([Polynomial<i64>; 2], Polynomial<i64>) {
    // Generate a public and secret key
    let sk = gen_binary_poly(size);
    let a = gen_uniform_poly(size, modulus);
    let e = gen_normal_poly(size);
    let b = polyadd(polymul(-a.clone(), sk.clone(), modulus, poly_mod.clone()), -e, modulus, poly_mod);
    
    // Return public key (b, a) as an array and secret key (sk)
    ([b, a], sk)  // Using an array instead of a Vec
}

fn encrypt(pk: [Polynomial<i64>; 2], size: usize, q: i64, t: i64, poly_mod: Polynomial<i64>, pt: Vec<i64>) -> [Polynomial<i64>; 2] {
    //Encrypt an integer or list of integers
    //Args:
    //	pk: public-key
    //	size: size of polynomials
    //	q: ciphertext modulus
    //	t: plaintext modulus
    //	poly_mod: polynomial modulus
    //	pt: array to be encrypted
    //Returns:
    //	Array representing a ciphertext
	
    //encode pt into a plaintext polynomial if pt is an int, otherwise encode as a full polynomial
	let mut m = pt;
	m.resize(size, 0);
    let delta = q / t;
    let mut scaled_m = vec![0i64;size];
	for i in 0..size {
		scaled_m[i] = delta*m[i] % q;
	}
	let scaled_m_poly = Polynomial::new(scaled_m);
    let e1 = gen_normal_poly(size);
    let e2 = gen_normal_poly(size);
    let u = gen_binary_poly(size);
    let ct0 = polyadd(
			polyadd(
				polymul(pk[0].clone(), u.clone(), q, poly_mod.clone()),
				e1, q, poly_mod.clone()),
			scaled_m_poly, q, poly_mod.clone()
		);
    let ct1 = polyadd(
			polymul(pk[1].clone(), u.clone(), q, poly_mod.clone()),
			e2, q, poly_mod.clone()
        );
	[ct0, ct1]
}

fn decrypt(sk: Polynomial<i64>, size: usize, q: i64, t: i64, poly_mod: Polynomial<i64>, ct: [Polynomial<i64>;2]) -> Vec<i64> {
    //Decrypt a ciphertext
    //Args:
		//sk: secret-key
        //size: size of polynomials
        //q: ciphertext modulus
        //t: plaintext modulus
        //poly_mod: polynomial modulus
        //ct: ciphertext array
    //Returns:
        //Array representing the plaintext
    let scaled_pt = polyadd(
            polymul(ct[1].clone(), sk, q, poly_mod.clone()),
            ct[0].clone(), q, poly_mod.clone()
        );
	let mut pt = vec![];
	let mut s = 0f64;
	for i in 0..size {
		s = scaled_pt.coeffs()[i] as f64 * t as f64 / q as f64;
		pt.push(s.round() as i64 % t);
	}
    pt
}

fn main() {
    // Encryption scheme parameters
    let (n, q, t, poly_mod) = parameters();

    // Keygen: Convert q from usize to i64
    let (pk, sk) = keygen(n, q.try_into().unwrap(), poly_mod.clone());
	
	let ct = encrypt(pk.clone(), n, q.try_into().unwrap(), t.try_into().unwrap(), poly_mod.clone(), vec![2,4,5,6]);
	let pt = decrypt(sk.clone(), n, q.try_into().unwrap(), t.try_into().unwrap(), poly_mod.clone(), ct);
    
    // Convert keys to vector of integers
    let keys = json!({
        "secret": sk.coeffs(),
        "public_b": pk[0].coeffs(),
        "public_a": pk[1].coeffs()
    });

    // Print keys in JSON format
    println!("{}", serde_json::to_string(&keys).unwrap());
	println!("{:?}", pt);
}

