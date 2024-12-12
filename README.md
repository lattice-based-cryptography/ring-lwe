# lattice-based-rust
Lattice-based encryption methods (ring-LWE, module-LWE) in pure Rust.

**Description**: This provides the basic PKE (keygen, encryption, and decryption) operations for the ring learning-with-errors scheme.

**Disclaimer**: This is not secure. The parameters are set to small values, and it is not written in constant time nor resistant to other side-channel attacks. This is intended for educational use and not for real-world applications.

**See**: [open-encrypt](https://github.com/jacksonwalters/open-encrypt)

**Usage**: In the `src` directory,

`cargo build`

To build the binary.

`cargo run -- keygen`

This will generate a public/secret keypair. 

- ring-LWE: The public key is the concatenated coefficients of two polynomials of degree `n`. The secret key is the coefficients of a binary polynomial of degree `n`.
- module-LWE: The public key is a matrix of polynomials of degree `n` and a vector of polynomials of degree `n`. The secret key is a vector of polynomials of degree `n`.

`cargo run -- encrypt public_key message`

Generates the ciphertext.

- ring-LWE: the coefficients of two polynomials of degree `n`
- module-LWE: a vector of polynomials of degree `n`, and a polynomial of degree `n`

`cargo run -- decrypt secret_key ciphertext`

Decrypts the ciphertext given a secret key specified by the coefficients of a binary polynomial, printing the plaintext message.
