# lattice-based-rust
Lattice-based encryption methods (ring-LWE, module-LWE) in pure Rust.

This provides the basic PKE (keygen, encryption, and decryption) operations for the ring learning-with-errors scheme.

**Disclaimer**: The parameters are set to small values. This is not secure. This is intended for educational use and not for real-world applications.

**See**: [open-encrypt](https://github.com/jacksonwalters/open-encrypt)

**Usage**: In the `src` directory,

`cargo build`

To build the binary.

`cargo run -- keygen`

This will generate a public/secret keypair. The public key is the concatenated coefficients of two polynomials of degree `n`. The secret key is the coefficients of a binary polynomial of degree `n`.

`cargo run -- encrypt public_key message`

Returns the ciphertext, the coefficients of two polynomials of degree `n`, corresponding to a public key and plaintext message. 

`cargo run -- decrypt secret_key ciphertext`

Decrypts the ciphertext given a secret key specified by the coefficients of a binary polynomial.
