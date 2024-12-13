use polynomial_ring::Polynomial;
use module_lwe::ring_mod::{polyadd,polysub};
use module_lwe::{Parameters, add_vec, mul_mat_vec_simple, transpose, mul_vec_simple, gen_small_vector};

pub fn encrypt(
    a: &Vec<Vec<Polynomial<i64>>>,
    t: &Vec<Polynomial<i64>>,
    m_b: Vec<i64>,
    f: &Polynomial<i64>,
    q: i64,
    r: &Vec<Polynomial<i64>>,
    e1: &Vec<Polynomial<i64>>,
    e2: &Polynomial<i64>,
) -> (Vec<Polynomial<i64>>, Polynomial<i64>) {
    //compute nearest integer to q/2
    let half_q = (q as f64 / 2.0 + 0.5) as i64;

    // Convert binary message to polynomial
    let m = Polynomial::new(vec![half_q])*Polynomial::new(m_b);

    // Compute u = a^T * r + e_1 mod q
    let u = add_vec(&mul_mat_vec_simple(&transpose(a), r, q, f), e1, q, f);

    // Compute v = t * r + e_2 - m mod q
    let v = polysub(&polyadd(&mul_vec_simple(t, r, q, f), e2, q, f), &m, q, f);

    (u, v)
}

//function to encrypt a message given a public_key string
pub fn encrypt_string(pk_string: &String, message_string: &String, params: &Parameters) -> String {

    //get parameters
    let (n, k, q, f) = (params.n, params.k, params.q, &params.f);

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

    let ciphertext_str = ciphertext_list.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",");

    ciphertext_str
}