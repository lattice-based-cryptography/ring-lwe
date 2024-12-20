#[cfg(test)]  // This makes the following module compile only during tests
mod tests {
    use crate::keygen::{keygen, keygen_string};
    use crate::encrypt::{encrypt, encrypt_string};
    use crate::decrypt::{decrypt, decrypt_string};
    use ring_lwe::{Parameters, polyadd, polymul, mod_coeffs,nearest_int};
    use polynomial_ring::Polynomial;

    // Test for basic keygen/encrypt/decrypt of a message
    #[test]
    pub fn test_basic() {
        let message = String::from("hello");
        let params = Parameters::default();  // Adjust this if needed
        let keypair = keygen_string(&params);
        let pk_string = keypair.get("public").unwrap();
        let sk_string = keypair.get("secret").unwrap();
        let ciphertext_string = encrypt_string(&pk_string, &message, &params);
        let decrypted_message = decrypt_string(&sk_string, &ciphertext_string, &params);
        assert_eq!(message, decrypted_message, "test failed: {} != {}", message, decrypted_message);
    }

    // Test homomorphic addition property: ensure sum of encrypted plaintexts decrypts to plaintext sum
    #[test]
    pub fn test_hom_add() {
        let params = Parameters::default();  // Adjust this if needed

        // Create polynomials from ints
        let m0_poly = Polynomial::new({
            let mut v = vec![0i64; params.n];
            v[0] = 2;
            v
        });
        let m1_poly = Polynomial::new({
            let mut v = vec![0i64; params.n];
            v[0] = 2;
            v
        });

        let plaintext_sum = &m0_poly + &m1_poly;
        let keypair = keygen(&params);
        let pk = keypair.0;
        let sk = keypair.1;

        // Encrypt plaintext messages
        let u = encrypt(&pk, &m0_poly, &params);
        let v = encrypt(&pk, &m1_poly, &params);

        // Compute sum of encrypted data
        let ciphertext_sum = [&u.0 + &v.0, &u.1 + &v.1];

        // Decrypt ciphertext sum u+v
        let decrypted_sum = decrypt(&sk, &ciphertext_sum, &params);

        assert_eq!(decrypted_sum, plaintext_sum, "test failed: {} != {}", decrypted_sum, plaintext_sum);
    }

    // Test homomorphic multiplication property: product of encrypted plaintexts should decrypt to plaintext product
    #[test]
    pub fn test_hom_prod() {

        let params = Parameters::default();
        let (n, q, t, f) = (params.n, params.q, params.t, &params.f);

        //create polynomials from ints
        let m0_poly = Polynomial::new({
            let mut v = vec![0i64; n];
            v[0] = 2;
            v
        });
        let m1_poly = Polynomial::new({
            let mut v = vec![0i64; n];
            v[0] = 3;
            v
        });
        //generate the keypair
        let (pk, sk) = keygen(&params);
        //encrypt plaintext messages
        let u = encrypt(&pk,&m0_poly,&params);
        let v = encrypt(&pk,&m1_poly,&params);
        //compute plaintext product
        let plaintext_prod = &m0_poly * &m1_poly;
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
}