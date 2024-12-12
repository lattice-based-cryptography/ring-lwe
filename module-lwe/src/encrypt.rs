use polynomial_ring::Polynomial;
use module_lwe::ring_mod::{polyadd,polysub};
use module_lwe::{add_vec, mul_mat_vec_simple, transpose, mul_vec_simple};

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

    // Compute u = A^T * r + e_1 mod q
    let u = add_vec(&mul_mat_vec_simple(&transpose(a), r, q, f), e1, q, f);

    // Compute v = t * r + e_2 - m mod q
    let v = polysub(&polyadd(&mul_vec_simple(t, r, q, f), e2, q, f), &m, q, f);

    (u, v)
}
