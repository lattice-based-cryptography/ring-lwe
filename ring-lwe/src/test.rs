
use crate::keygen::{keygen,keygen_string};
use crate::encrypt::{encrypt,encrypt_string};
use crate::decrypt::{decrypt,decrypt_string};
use ring_lwe::{Parameters,polyadd,polymul,polyinv,mod_coeffs};
use polynomial_ring::Polynomial;

//test basic keygen/encrypt/decrypt of a message
pub fn test_basic(message: &String, params: &Parameters) {
    let keypair = keygen_string(&params);
    let pk_string = keypair.get("public").unwrap();
    let sk_string = keypair.get("secret").unwrap();
    let ciphertext_string = encrypt_string(&pk_string,message,&params);
    let decrypted_message = decrypt_string(&sk_string,&ciphertext_string,&params);
    let test_passed = *message == decrypted_message;
    debug_assert!(test_passed, "test failed: {} != {}", *message, decrypted_message);
    println!("test passed");
}

//test homomorphic addition property: ensure sum of encrypted plaintexts decrypts to plaintext sum
pub fn test_hom_add(m0: &String, m1: &String, params: &Parameters) {

    //create polynomials from message strings
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
    //compute plaintext sum
    let plaintext_sum = &m0_poly + &m1_poly;
    //generate the keypair
    let keypair = keygen(&params);
    //get public and secret keys
    let pk = keypair.0;
    let sk = keypair.1;
    //encrypt plaintext messages
    let u = encrypt(&pk,&m0_poly,&params);
    let v = encrypt(&pk,&m1_poly,&params);
    //compute sum of encrypted data
    let ciphertext_sum = [&u.0 + &v.0, &u.1 + &v.1];
    //decrypt ciphertext sum u+v
    let decrypted_sum = decrypt(&sk,&ciphertext_sum,&params);
    //assert the plaintext sum and decrypted ciphertext sums are the same
    debug_assert!(decrypted_sum == plaintext_sum,"test failed: {:?} != {:?}",plaintext_sum, decrypted_sum);
    println!("test passed!")
}

//test homomorphic multiplcation property: product of encrypted plaintexts should decrypt to plaintext product
pub  fn test_hom_prod(m0: &String, m1: &String, params: &Parameters) {
    //read in parameters
    let (n, q, t, f) = (params.n, params.q, params.t, &params.f);

    //create polynomials from message strings
    //TO-DO: fix multiplcation
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
    //generate the keypair
    let keypair = keygen(&params);
    //get public and secret keys
    let pk = keypair.0;
    let sk = keypair.1;
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
    let decrypted_prod = mod_coeffs(Polynomial::new(ciphertext_prod.coeffs().iter().map(|&coeff| (coeff+(delta*delta)/2) / (delta * delta) ).collect::<Vec<_>>()),t);
    
    //print results
    println!("input polys m1={:?} m2={:?}",m0_poly, m1_poly);
    println!("delta = {}",delta);
    println!("delta^2 = {}",delta * delta);
    println!("plaintext product = {}", m0_int * m1_int);
    println!("ciphertext_prod = {:?}",ciphertext_prod);
    println!("decrypted_product = {:?}",decrypted_prod);

    debug_assert!(decrypted_prod == plaintext_prod,"test failed: {:?} != {:?}",plaintext_prod, decrypted_prod);
    println!("test passed!");
}