mod keygen;
mod encrypt;
mod decrypt;

use crate::keygen::keygen;
use crate::encrypt::encrypt;
use crate::decrypt::decrypt;
use ring_lwe::parameters;
use std::collections::HashMap;

use std::env;

use polynomial_ring::Polynomial;

fn main() {
    let args: Vec<String> = env::args().collect();
    let method = if args.len() > 1 {
        &args[1]
    } else {
        ""
    };

    // Encryption scheme parameters
    let (n, q, t, poly_mod) = parameters();

    if method == "keygen" {
        // Keygen: Convert n and q from usize to i64
        let (pk, sk) = keygen(n, q.try_into().unwrap(), &poly_mod);
        let mut pk_coeffs: Vec<i64> = Vec::with_capacity(2*n);
        pk_coeffs.extend(pk[0].coeffs());
        pk_coeffs.extend(pk[1].coeffs());
        //convert the secret key and public key to strings
        // Convert the public key coefficients to a comma-separated string
        let pk_coeffs_str = pk_coeffs.iter()
            .map(|coef| coef.to_string())
            .collect::<Vec<String>>()
            .join(",");
        // Convert the secret key coefficients to a comma-separated string
        let sk_coeffs_str = sk.coeffs().iter()
            .map(|coef| coef.to_string())
            .collect::<Vec<String>>()
            .join(",");
        //store public/secret keys in HashMap
        let mut keys: HashMap<String, String> = HashMap::new();
        keys.insert(String::from("secret"), sk_coeffs_str);
        keys.insert(String::from("public"), pk_coeffs_str);
        // Print keys in JSON format
        println!("{:?}", keys);
    }

    //encrypt given public key and message as args
    if method == "encrypt" {
        // Get the public key from the string and format as two Polynomials
        let pk_string = &args[2];
        let pk_arr: Vec<i64> = pk_string
            .split(',')
            .filter_map(|x| x.parse::<i64>().ok())
            .collect();

        let pk_b = Polynomial::new(pk_arr[..n].to_vec());
        let pk_a = Polynomial::new(pk_arr[n..].to_vec());
        let pk = [pk_b, pk_a];

        // Define the integers to be encrypted
        let message = &args[3];
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
            let ciphertext = encrypt(&pk, n, q.try_into().unwrap(), t.try_into().unwrap(), &poly_mod, &message_block);
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

    if method == "decrypt" {
        //get the secret key and format as polynomial
        let sk_string = &args[2];
        let sk_coeffs: Vec<i64> = sk_string
            .split(',')
            .filter_map(|x| x.parse::<i64>().ok())
            .collect();
        let sk = Polynomial::new(sk_coeffs);

        // Get the ciphertext to be decrypted
        let ciphertext_string = &args[3];
        let ciphertext_array: Vec<i64> = ciphertext_string
        .split(',')
        .map(|s| s.parse::<i64>().unwrap())
        .collect();

        let num_bytes = ciphertext_array.len() / (2 * n);
        let mut decrypted_message = String::new();

        for i in 0..num_bytes {
            let c0 = Polynomial::new(ciphertext_array[2 * i * n..(2 * i + 1) * n].to_vec());
            let c1 = Polynomial::new(ciphertext_array[(2 * i + 1) * n..(2 * i + 2) * n].to_vec());
            let ct = [c0, c1];

            // Decrypt the ciphertext
            let decrypted_poly = decrypt(&sk, n, q.try_into().unwrap(), t.try_into().unwrap(), &poly_mod, &ct);

            // Convert the coefficients to characters and append to the message
            decrypted_message.push_str(
                &decrypted_poly
                    .coeffs()
                    .iter()
                    .map(|&coeff| coeff as u8 as char)
                    .collect::<String>(),
            );
        }

        // Print the decrypted message
        println!("{}", decrypted_message);
        
    }

}