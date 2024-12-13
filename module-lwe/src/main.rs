mod keygen;
mod encrypt;
mod decrypt;

use crate::keygen::keygen;
use crate::encrypt::encrypt;
use crate::decrypt::decrypt;
use module_lwe::{parameters,gen_small_vector};
use std::env;
use std::collections::HashMap;

use polynomial_ring::Polynomial;

//function to generate public/secret keys as key:value pairs
fn keygen_string() -> HashMap<String, String> {

    // Parameters and inputs
    let (n, q, k, f) = parameters();

    //generate public, secret keys
    let (a,t,sk) = keygen(n,q as i64,k,&f);
    let pk = (a,t);

    // Convert public key to a flattened list of coefficients
    let mut pk_coeffs: Vec<i64> = pk.0
        .iter()
        .flat_map(|row| {
            row.iter().flat_map(|poly| {
                let mut coeffs = poly.coeffs().to_vec();
                coeffs.resize(n, 0); // Resize to include leading zeros up to size `n`
                coeffs
            })
        })
        .collect();
    pk_coeffs.extend(
        pk.1.iter()
        .flat_map(|poly| {
            let mut coeffs = poly.coeffs().to_vec();
            coeffs.resize(n, 0); // Resize to include leading zeros up to size `n`
            coeffs
        })
    );

    // Convert secret key to a flattened list of coefficients
    let sk_coeffs: Vec<i64> = sk
        .iter()
        .flat_map(|poly| {
            let mut coeffs = poly.coeffs().to_vec();
            coeffs.resize(n, 0); // Resize to include leading zeros up to size `n`
            coeffs
        })
    .collect();

    // Convert the public/secret key coefficients to a comma-separated string
    let pk_coeffs_str = pk_coeffs.iter()
        .map(|coef| coef.to_string())
        .collect::<Vec<String>>()
        .join(",");
    let sk_coeffs_str = sk_coeffs.iter()
        .map(|coef| coef.to_string())
        .collect::<Vec<String>>()
        .join(",");
    
    //store the secret/public key in a HashMap
    let mut keys: HashMap<String, String> = HashMap::new();
    keys.insert(String::from("secret"), sk_coeffs_str);
    keys.insert(String::from("public"), pk_coeffs_str);
    
    keys
}

//function to encrypt a message given a public_key string
fn encrypt_string(pk_string: &String, message_string: &String) -> String {
    // Parameters and inputs
    let (n, q, k, f) = parameters();

    // Randomly generated values for r, e1, and e2
    let r = gen_small_vector(n, k);
    let e1 = gen_small_vector(n, k);
    let e2 = gen_small_vector(n, 1)[0].clone(); // Single polynomial

    // Parse public key
    
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
        let u_flattened: Vec<i64> = u.iter()
            .flat_map(|poly| {
                let mut coeffs = poly.coeffs().to_vec();
                coeffs.resize(n, 0); // Resize to include leading zeros up to size `n`
                coeffs
            })
            .collect();
        let mut v_flattened: Vec<i64> = v.coeffs().to_vec();
        v_flattened.resize(n,0);
        ciphertext_list.extend(u_flattened);
        ciphertext_list.extend(v_flattened);
    }

    //return ciphertext_str
    let ciphertext_str = ciphertext_list.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",");

    ciphertext_str
}

//decrypt a ciphertext string given a secret key
fn decrypt_string(sk_string: &String, ciphertext_string: &String) -> String {

    // Parameters and inputs
    let (n, q, k, f) = parameters();
    
    // Convert the secret key string into a Vec<Polynomial<i64>>
    let sk_array: Vec<i64> = sk_string.split(',')
        .filter_map(|s| s.parse().ok())
        .collect();
    let sk: Vec<Polynomial<i64>> = sk_array.chunks(n)
        .map(|chunk| Polynomial::new(chunk.to_vec()))
        .collect();
    
    // Parse ciphertext into u and v
    let ciphertext_list: Vec<i64> = ciphertext_string.split(',')
        .filter_map(|s| s.parse().ok())
        .collect();
    let block_size = (k + 1) * n;
    let num_blocks = ciphertext_list.len() / block_size;

    let mut message_binary = vec![];
    
    for i in 0..num_blocks {
        // Get u and v for this block
        let u_array = &ciphertext_list[i * block_size..i * block_size + k * n];
        let v_array = &ciphertext_list[i * block_size + k * n..(i + 1) * block_size];
            
        let u: Vec<Polynomial<i64>> = u_array.chunks(n)
            .map(|chunk| Polynomial::new(chunk.to_vec()))
            .collect();
        let v = Polynomial::new(v_array.to_vec());
            
        // Decrypt the ciphertext
        let mut m_b = decrypt(&sk, q as i64, &f, &u, &v);
        m_b.resize(n,0);
            
        message_binary.extend(m_b);
    }
    
    // Group the bits back into bytes (8 bits each)
    let byte_chunks: Vec<String> = message_binary.chunks(8)
        .map(|chunk| chunk.iter().map(|bit| bit.to_string()).collect())
        .collect();
        
    // Convert each binary string back into a character
    let message_string: String = byte_chunks.iter()
        .map(|byte| char::from_u32(i64::from_str_radix(byte, 2).unwrap() as u32).unwrap())
        .collect();
        
    message_string
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let method = if args.len() > 1 {
        &args[1]
    } else {
        ""
    };

    if method == "keygen" {
        if args.len() != 2 {
            println!("Usage: cargo run -- keygen");
            return;
        }
        println!("{:?}", keygen_string());
    }

    if method == "encrypt" {
        if args.len() != 4 {
            println!("Usage: cargo run -- encrypt <public_key> <message_string>");
            return;
        }
        let pk_string = &args[2];
        let message_string = &args[3];
        let ciphertext_string = encrypt_string(pk_string,message_string);
        println!("{}",ciphertext_string);
    }

    if method == "decrypt" {
        if args.len() != 4 {
            println!("Usage: cargo run -- decrypt <secret_key> <ciphertext>");
            return;
        }
        let sk_string = &args[2];
        let ciphertext_string = &args[3];
        let plaintext_message = decrypt_string(sk_string,ciphertext_string);
        println!("{}",plaintext_message);
    }
}