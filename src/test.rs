#[cfg(test)]  // This makes the following module compile only during tests
mod tests {
    use crate::keygen::{keygen, keygen_string};
    use crate::encrypt::{encrypt, encrypt_string};
    use crate::decrypt::{decrypt, decrypt_string};
    use ring_lwe::{Parameters, polyadd, polymul, polymul_fast, mod_coeffs, nearest_int, gen_uniform_poly};
    use ntt::omega;
    use polynomial_ring::Polynomial;

    // Test for basic keygen/encrypt/decrypt of a message
    #[test]
    pub fn test_basic() {
        let seed = None; //set the random seed
        let message = String::from("hello");
        let params = Parameters::default();
        let keypair = keygen_string(&params,seed);
        let pk_string = keypair.get("public").unwrap();
        let sk_string = keypair.get("secret").unwrap();
        let ciphertext_string = encrypt_string(&pk_string, &message, &params,seed);
        let decrypted_message = decrypt_string(&sk_string, &ciphertext_string, &params);
        assert_eq!(message, decrypted_message, "test failed: {} != {}", message, decrypted_message);
    }

    // Test homomorphic addition property: ensure sum of encrypted plaintexts decrypts to plaintext sum
    #[test]
    pub fn test_hom_add() {

        let seed = None; //set the random seed
        let params = Parameters::default();  // Adjust this if needed
		let (t, f) = (params.t, &params.f);

        // Create polynomials from ints
        let m0_poly = Polynomial::new(vec![1, 0, 1]);
        let m1_poly = Polynomial::new(vec![0, 0, 1]);

        let plaintext_sum = polyadd(&m0_poly, &m1_poly, t, &f);
        let (pk, sk) = keygen(&params,seed);

        // Encrypt plaintext messages
        let u = encrypt(&pk, &m0_poly, &params, seed);
        let v = encrypt(&pk, &m1_poly, &params, seed);

        // Compute sum of encrypted data
        let ciphertext_sum = [&u.0 + &v.0, &u.1 + &v.1];

        // Decrypt ciphertext sum u+v
        let decrypted_sum = decrypt(&sk, &ciphertext_sum, &params);

        assert_eq!(decrypted_sum, plaintext_sum, "test failed: {} != {}", decrypted_sum, plaintext_sum);
    }

    // Test homomorphic multiplication property: product of encrypted plaintexts should decrypt to plaintext product
    #[test]
    pub fn test_hom_prod() {

        let seed = None; //set the random seed
        let mut params = Parameters::default();
        let (q, t, f) = (params.q, params.t, &params.f);
        params.q = q*q;
        params.omega = omega(q*q, 2*params.n);

        //create polynomials from ints
        let m0_poly = Polynomial::new(vec![1, 0, 1]);
        let m1_poly = Polynomial::new(vec![0, 0, 1]);

        // Generate the keypair
        let (pk, sk) = keygen(&params,seed);

        // Encrypt plaintext messages
        let u = encrypt(&pk, &m0_poly, &params, seed);
        let v = encrypt(&pk, &m1_poly, &params, seed);

        let plaintext_prod = polymul(&m0_poly, &m1_poly, t, &f);
        //compute product of encrypted data, using non-standard multiplication
        let c0 = polymul(&u.0,&v.0,q*q,&f);
        let u0v1 = &polymul(&u.0,&v.1,q*q,&f);
        let u1v0 = &polymul(&u.1,&v.0,q*q,&f);
        let c1 = polyadd(u0v1,u1v0,q*q,&f);
        let c2 = polymul(&u.1,&v.1,q*q,&f);
        let c = (c0, c1, c2);
        //compute c0 + c1*s + c2*s*s
        let c1_sk = &polymul(&c.1,&sk,q*q,&f);
        let c2_sk_squared = &polymul(&polymul(&c.2,&sk,q*q,&f),&sk,q*q,&f);
        let ciphertext_prod = polyadd(&polyadd(&c.0,c1_sk,q*q,&f),c2_sk_squared,q*q,&f);
        //let delta = q / t, divide coeffs by 1 / delta^2
        let delta = q / t;
        let decrypted_prod = mod_coeffs(Polynomial::new(ciphertext_prod.coeffs().iter().map(|&coeff| nearest_int(coeff,delta * delta) ).collect::<Vec<_>>()),t);
        
        assert_eq!(plaintext_prod, decrypted_prod, "test failed: {} != {}", plaintext_prod, decrypted_prod);
    }

    // Test fast polynomial multiplcation using NTT for small example polynomials
    #[test]
    pub fn test_polymul_fast() {
        let p: i64 = 17; // Prime modulus
        let n: usize = 8;  // Length of the NTT (must be a power of 2)
        let omega = omega(p, n); // n-th root of unity
        let params = Parameters::default();
    
        // Input polynomials (padded to length `n`)
        let a = Polynomial::new(vec![1, 2, 3, 4]);
        let b = Polynomial::new(vec![5, 6, 7, 8]);
    
        let c_std = polymul(&a, &b, p, &params.f);
        let c_fast = polymul_fast(&a, &b, p, &params.f, omega);

        assert_eq!(c_std, c_fast, "test failed: {} != {}", c_std, c_fast);
    }

    // Test fast polynomial multiplication with the NTT for uniformly random polynomials degree n
    #[test]
    pub fn test_polymul_fast_uniform() {
        let seed = None; //set the random seed
        let params = Parameters::default();
    
        // Input polynomials (padded to length `n`)
        let a = gen_uniform_poly(params.n, params.q, seed);
        let b = gen_uniform_poly(params.n, params.q, seed);
    
        let c_std = polymul(&a, &b, params.q, &params.f);
        let c_fast = polymul_fast(&a, &b, params.q, &params.f, params.omega);

        assert_eq!(c_std, c_fast, "test failed: {} != {}", c_std, c_fast);
    }
}