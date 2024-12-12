mod keygen;
mod encrypt;

use crate::keygen::keygen;
use crate::encrypt::encrypt;
use module_lwe::{parameters,gen_small_vector};
use std::env;

use polynomial_ring::Polynomial;

fn main() {
    let args: Vec<String> = env::args().collect();
    let method = if args.len() > 1 {
        &args[1]
    } else {
        ""
    };

    // Parameters and inputs
    let (n, q, k, f) = parameters();

    if method == "keygen" {
        //generate public, secret keys
        let (a,t,sk) = keygen(n,q as i64,k,&f);
        let pk = (a,t);

        // Convert public and secret keys to lists of coefficients
        let mut pk_coeffs: Vec<i64> = pk.0.iter() 
            .flat_map(|row| row.iter().flat_map(|poly| poly.coeffs()))
            .cloned()
            .collect();
        pk_coeffs.extend(pk.1.iter().flat_map(|poly| poly.coeffs()).cloned()); 

        let sk_coeffs: Vec<i64> = sk.iter().flat_map(|poly| poly.coeffs()).cloned().collect(); 

        // Print public key coefficients
        println!("Public Key Coefficients:");
        println!("{:?}", pk_coeffs);

        // Print secret key coefficients
        println!("Secret Key Coefficients:");
        println!("{:?}", sk_coeffs);
    }

    //encrypt given public key and message as args
    if method == "encrypt" && args.len() > 2 {
        // Randomly generated values for r, e1, and e2
        let r = gen_small_vector(n, k);
        let e1 = gen_small_vector(n, k);
        let e2 = gen_small_vector(n, 1)[0].clone(); // Single polynomial

        // Parse public key
        let pk_string = &args[2];
        let pk_list: Vec<i64> = pk_string.split(',').map(|x| x.parse::<i64>().unwrap()).collect();

        let a: Vec<Vec<Polynomial<i64>>> = pk_list[..k * k * n]
            .chunks(k * n)
            .map(|chunk| {
                chunk.chunks(n).map(|coeffs| Polynomial::new(coeffs.to_vec())).collect()
            })
            .collect();

        let t: Vec<Polynomial<i64>> = pk_list[k * k * n..]
            .chunks(n)
            .map(|coeffs| Polynomial::new(coeffs.to_vec()))
            .collect();

        // Parse message
        let message_string = &args[3];
        let message_binary: Vec<i64> = message_string
            .bytes()
            .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1) as i64))
            .collect();

        // Break message into blocks
        let num_blocks = message_binary.len() / n;
        let message_blocks: Vec<Vec<i64>> = (0..num_blocks)
            .map(|i| message_binary[i * n..(i + 1) * n].to_vec())
            .collect();

        // Encrypt each block
        let mut ciphertext_list = vec![];
        for block in message_blocks {
            let (u, v) = encrypt(&a, &t, block, &f, q as i64, &r, &e1, &e2);
            let u_flattened: Vec<i64> = u.iter().flat_map(|poly| poly.coeffs()).cloned().collect();
            let v_flattened: Vec<i64> = v.coeffs().to_vec();
            ciphertext_list.extend(u_flattened);
            ciphertext_list.extend(v_flattened);
        }

        // Print ciphertext
        println!("{}", ciphertext_list.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(","));
    }
}