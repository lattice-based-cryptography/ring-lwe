mod keygen;
mod encrypt;
mod decrypt;

use crate::keygen::keygen_string;
use crate::encrypt::encrypt_string;
use crate::decrypt::decrypt_string;
use std::env;
use ring_lwe::Parameters;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Initialize struct with default values
    let mut params = Parameters::default();
    // Check for --params flag and get the updated values directly
    if let Some(pos) = args.iter().position(|x| x == "--params") {
        if args.len() > pos + 3 {
            params.n = args.get(pos + 1).and_then(|s| s.parse().ok()).unwrap_or(params.n);
            params.q = args.get(pos + 2).and_then(|s| s.parse().ok()).unwrap_or(params.q);
            params.k = args.get(pos + 3).and_then(|s| s.parse().ok()).unwrap_or(params.k);
        }
    }

    let method = if args.len() > 1 {&args[1]} else {""};

    if method == "test" {
        if args.len() != 3 && args.len() != 7 {
            println!("Usage: cargo run -- test <message>");
            return;
        }
        let message_string = &args[2];
        let keypair = keygen_string(&params);
        let pk_string = keypair.get("public").unwrap();
        let sk_string = keypair.get("secret").unwrap();
        let ciphertext_string = encrypt_string(&pk_string,message_string,&params);
        let decrypted_message = decrypt_string(&sk_string,&ciphertext_string,&params);
        let test_passed = *message_string == decrypted_message;
        println!("{} =? {}",*message_string,decrypted_message);
        println!("{}",test_passed);
    }

    if method == "keygen"{
        if args.len() != 2 && args.len() != 6 {
            println!("Usage: cargo run -- keygen");
            return;
        }
        let keypair = keygen_string(&params);
        println!("{:?}",keypair);
    }

    //encrypt given public key and message as args
    if method == "encrypt" {
        if args.len() != 4 && args.len() != 8 {
            println!("Usage: cargo run -- encrypt <public_key> <message_string>");
            return;
        }
        let pk_string = &args[2];
        let message = &args[3];
        let ciphertext_string = encrypt_string(pk_string,message,&params);
        println!("{}", ciphertext_string);
    }

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