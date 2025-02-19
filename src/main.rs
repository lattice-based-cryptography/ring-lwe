mod keygen;
mod encrypt;
mod decrypt;
mod utils;
mod test;

use crate::keygen::keygen_string;
use crate::encrypt::encrypt_string;
use crate::decrypt::decrypt_string;
use crate::utils::Parameters;
use std::env;
use polynomial_ring::Polynomial;

/// Main function to run the keygen, encrypt and decrypt functions
fn main() {
    let args: Vec<String> = env::args().collect();

    // Initialize struct with default values
    let mut params = Parameters::default();
    // Check for --params flag and get the updated values directly
    if let Some(pos) = args.iter().position(|x| x == "--params") {
        if args.len() > pos + 3 {
            params.n = args.get(pos + 1).and_then(|s| s.parse().ok()).unwrap_or(params.n);
            params.q = args.get(pos + 2).and_then(|s| s.parse().ok()).unwrap_or(params.q);
            params.t = args.get(pos + 3).and_then(|s| s.parse().ok()).unwrap_or(params.t);
            let mut poly_vec = vec![0i64;params.n+1];
            poly_vec[0] = 1;
            poly_vec[params.n] = 1;
            params.f = Polynomial::new(poly_vec);
        }
    }

    let method = if args.len() > 1 {&args[1]} else {""};

    //generate public and secret keys (parameters optional)
    if method == "keygen"{
        if args.len() != 2 && args.len() != 6 {
            println!("Usage: cargo run -- keygen");
            return;
        }
        let keypair = keygen_string(&params,None);
        println!("{:?}",keypair);
    }

    //encrypt given public key and message as args (parameters optional)
    if method == "encrypt" {
        if args.len() != 4 && args.len() != 8 {
            println!("Usage: cargo run -- encrypt <public_key> <message_string>");
            return;
        }
        let pk_string = &args[2];
        let message = &args[3];
        let ciphertext_string = encrypt_string(pk_string,message,&params,None);
        println!("{}", ciphertext_string);
    }

    //decrypt a messsage (parameters optional)
    if method == "decrypt" {
        if args.len() != 4 && args.len() != 8 {
            println!("Usage: cargo run -- decrypt <secret_key> <ciphertext>");
            return;
        }
        let sk_string = &args[2];
        let ciphertext_string = &args[3];
        let decrypted_message = decrypt_string(sk_string, ciphertext_string,&params);
        // Print the decrypted message
        println!("{}", decrypted_message);
    }

}