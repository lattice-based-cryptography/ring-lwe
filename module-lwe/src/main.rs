mod keygen;
mod encrypt;
mod decrypt;

use crate::keygen::keygen_string;
use crate::encrypt::encrypt_string;
use crate::decrypt::decrypt_string;
use std::env;

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