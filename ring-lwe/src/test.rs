#[cfg(test)]  // This makes the following module compile only during tests
mod tests {
    use crate::keygen::{keygen, keygen_string};
    use crate::encrypt::{encrypt, encrypt_string};
    use crate::decrypt::{decrypt, decrypt_string};
    use ring_lwe::{Parameters, polyadd, polymul, polyinv, mod_coeffs};
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
        let m0 = String::from("2");
        let m1 = String::from("3");
        let params = Parameters::default();  // Adjust this if needed

        // Create polynomials from message strings
        let m0_int: i64 = m0.parse().expect("Failed to parse integer.");
        let m1_int: i64 = m1.parse().expect("Failed to parse integer.");
        let m0_poly = Polynomial::new({
            let mut v = vec![0i64; params.n];
            v[0] = m0_int;
            v
        });
        let m1_poly = Polynomial::new({
            let mut v = vec![0i64; params.n];
            v[0] = m1_int;
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
        let m0 = String::from("2");
        let m1 = String::from("3");
        let params = Parameters::default();  // Adjust this if needed

        let (n, q, t, f) = (params.n, params.q, params.t, &params.f);

        // Create polynomials from message strings
        let m0_int: i64 = m0.parse().expect("Failed to parse integer.");
        let m1_int: i64 = m1.parse().expect("Failed to parse integer.");
        let m0_poly = Polynomial::new({
            let mut v = vec![0i64; n];
            v[0] = m0_int;
            v
        });
        let m1_poly = Polynomial::new({
            let mut v = vec![0i64; n];
            v[0] = m1_int;
            v
        });

        // Generate the keypair
        let keypair = keygen(&params);
        let pk = keypair.0;
        let sk = keypair.1;

        // Encrypt plaintext messages
        let u = encrypt(&pk, &m0_poly, &params);
        let v = encrypt(&pk, &m1_poly, &params);

        let plaintext_prod = &m0_poly * &m1_poly;

        // Compute product of encrypted data, using non-standard multiplication
        let c0 = polymul(&v.0, &v.1, q, &f);
        let u0v1 = &polymul(&u.0, &v.1, q, &f);
        let u1v0 = &polymul(&u.1, &v.0, q, &f);
        let c1 = polyinv(&polyadd(u0v1, u1v0, q, &f), q);
        let c2 = polymul(&u.0, &u.1, q, &f);
        let c = (c0, c1, c2);

        // Compute c0 + c1*s + c2*s*s
        let c1_sk = &polymul(&c.1, &sk, q, &f);
        let c2_sk_squared = &polymul(&polymul(&c.2, &sk, q, &f), &sk, q, &f);
        let ciphertext_prod = polyadd(&polyadd(&c.0, c1_sk, q, &f), c2_sk_squared, q, &f);

        // Let delta = q / t, divide coeffs by 1 / delta^2
        let delta = q / t;
        let decrypted_prod = mod_coeffs(Polynomial::new(ciphertext_prod.coeffs().iter().map(|&coeff| coeff / (delta * delta) ).collect::<Vec<_>>()), q);

        assert_eq!(plaintext_prod, decrypted_prod, "test failed: {} != {}", plaintext_prod, decrypted_prod);
    }
}
