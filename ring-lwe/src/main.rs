mod keygen;
mod encrypt;
mod decrypt;

use crate::keygen::keygen;
use crate::encrypt::encrypt;
use crate::decrypt::decrypt;
use ring_lwe::parameters;
use serde_json::json;

use std::env;

use polynomial_ring::Polynomial;

fn main() {
    // Encryption scheme parameters
    let (n, q, t, poly_mod) = parameters();

    // Keygen: Convert n and q from usize to i64
    let (pk, sk) = keygen(n, q.try_into().unwrap(), &poly_mod);
    
    // Convert keys to vector of integers
    let keys = json!({
        "secret": sk.coeffs(),
        "public_b": pk[0].coeffs(),
        "public_a": pk[1].coeffs()
    });

    // Print keys in JSON format
    println!("{}", serde_json::to_string(&keys).unwrap());

    let args: Vec<String> = env::args().collect();

    if args.len() > 2 {
        // Get the public key from the string and format as two Polynomials
        let pk_string = &args[1];
        let pk_arr: Vec<i64> = pk_string
            .split(',')
            .filter_map(|x| x.parse::<i64>().ok())
            .collect();

        let pk_b = Polynomial::new(pk_arr[..n].to_vec());
        let pk_a = Polynomial::new(pk_arr[n..].to_vec());
        let pk = [pk_b, pk_a];

        // Define the integers to be encrypted
        let message = &args[2];
        let message_bytes: Vec<String> = message
            .bytes()
            .map(|byte| format!("{:b}", byte))
            .collect();

        let message_ints: Vec<i64> = message_bytes
            .iter()
            .filter_map(|byte| i64::from_str_radix(byte, 2).ok())
            .collect();

        // Convert message integers into a vector of Polynomials
        let message_blocks: Vec<Polynomial<i64>> = message_ints
            .chunks(n)
            .map(|chunk| Polynomial::new(chunk.to_vec()))
            .collect();

        // Encrypt each integer message block
        let mut ciphertext_list: Vec<i64> = Vec::new();
        for message_block in message_blocks {
            let ciphertext = encrypt(pk.clone(), n, q.try_into().unwrap(), t.try_into().unwrap(), &poly_mod, message_block);
            ciphertext_list.extend(ciphertext.0.coeffs());
            ciphertext_list.extend(ciphertext.1.coeffs());
        }

        // Format the ciphertext list as a comma-separated string
        let ciphertext_string = ciphertext_list
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(",");
        println!("{}", ciphertext_string);
    }

}