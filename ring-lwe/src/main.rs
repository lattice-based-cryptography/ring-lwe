mod keygen;
mod encrypt;
mod decrypt;

use crate::keygen::keygen_string;
use crate::encrypt::encrypt_string;
use crate::decrypt::decrypt_string;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let method = if args.len() > 1 {&args[1]} else {""};

    if method == "test" {
        if args.len() != 3 {
            println!("Usage: cargo run -- test <message>");
            return;
        }
        let message_string = &args[2];
        let keypair = keygen_string();
        let pk_string = keypair.get("public").unwrap();
        let sk_string = keypair.get("secret").unwrap();
        let ciphertext_string = encrypt_string(&pk_string,message_string);
        let decrypted_message = decrypt_string(&sk_string,&ciphertext_string);
        let test_passed = *message_string == decrypted_message;
        println!("{} =? {}",*message_string,decrypted_message);
        println!("{}",test_passed);
    }

    if method == "keygen"{
        if args.len() != 2 {
            println!("Usage: cargo run -- keygen");
            return;
        }
        let keypair = keygen_string();
        println!("{:?}",keypair);
    }

    //encrypt given public key and message as args
    if method == "encrypt" {
        if args.len() != 4 {
            println!("Usage: cargo run -- encrypt <public_key> <message_string>");
            return;
        }
        let pk_string = &args[2];
        let message = &args[3];
        let ciphertext_string = encrypt_string(pk_string,message);
        println!("{}", ciphertext_string);
    }

    if method == "decrypt" {
        if args.len() != 4 {
            println!("Usage: cargo run -- decrypt <secret_key> <ciphertext>");
            return;
        }
        let sk_string = &args[2];
        let ciphertext_string = &args[3];
        let decrypted_message = decrypt_string(sk_string, ciphertext_string);
        // Print the decrypted message
        println!("{}", decrypted_message);
    }

}