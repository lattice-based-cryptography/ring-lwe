# ring-LWE

![example workflow](https://github.com/jacksonwalters/lattice-based-rust/actions/workflows/basic.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/ring-lwe.svg)](https://crates.io/crates/ring-lwe)

Implmentation of lattice-based encryption method ring-LWE in pure Rust.

## Description

This provides the basic PKE (keygen, encryption, and decryption) operations for the ring learning-with-errors scheme.

## Disclaimer

This is not secure. It is not written in constant-time nor resistant to other side-channel attacks. This is intended for educational use and not for real-world applications.

## Build and test

 In the `src` directory,

`cargo build`

To build the binary.

`cargo test`

- Performs keygen/encrypt/decrypt for a test message.
- Checks homomorphic addition and multiplcation hold for small values.

## Keygen

_Note_: Parameters optional.

- `cargo run -- keygen --n 512 --q 12289 --t 2`

where `n` is the polynomial degree, `q` is the ciphertext modulus, `t` is the plaintext modulus.

If ommitted, the default parameters will be used.

`cargo run -- keygen`

This will generate a public/secret keypair printed to the console. 

To save the key files to `public.key` and `secret.key`, use the `--save-keys` flag:

`cargo run -- keygen --n 512 --q 12289 --t 2 --save-keys`

## Encryption

To encrypt a message using the public key using command line arguments:

`cargo run -- encrypt <public_key> <message>`

To encrypt a message using a public key file:

`cargo run -- encrypt --pubkey-file public.key "Hello, world!" --n 512 --q 1024 --t 3`

## Decryption

To decrypt a message using the secret key using command line arguments:

`cargo run -- decrypt <secret_key> <ciphertext>`

To decrypt a message using the secret key file:

`cargo run -- decrypt --secret-file secret.key "<CIPHERTEXT>" --n 512 --q 12289 --t 2`

**Benchmarks**:

| n    | q     | t | keygen    | encrypt   | decrypt   | keygen_string | encrypt_string | decrypt_string |
|------|-------|---|-----------|-----------|-----------|---------------|----------------|----------------|
| 256  | 12289 | 2 | 41.565 µs | 70.024 µs | 29.741 µs | 69.703 µs     | 99.181 µs      | 43.751 µs      |
| 512  | 12289 | 2 | 84.940 µs | 150.17 µs | 65.439 µs | 141.31 µs     | 210.94 µs      | 95.640 µs      |
| 1024 | 12289 | 2 | 183.50 µs | 326.54 µs | 145.40 µs | 293.69 µs     | 445.11 µs      | 200.24 µs      |