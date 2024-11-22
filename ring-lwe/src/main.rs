use ring_lwe::*; // Import your library

fn main() {
    // Retrieve parameters
    let (n, q, t, poly_mod) = parameters();
    println!("Parameters: n = {}, q = {}, t = {}, poly_mod = {:?}", n, q, t, poly_mod);

    // Generate and print a binary polynomial
    let binary_poly = gen_binary_poly(n);
    println!("Binary polynomial: {:?}", binary_poly);

    // Generate and print a uniform polynomial
    let uniform_poly = gen_uniform_poly(n, q as i64);
    println!("Uniform polynomial: {:?}", uniform_poly);

    // Generate and print a normal polynomial
    let normal_poly = gen_normal_poly(n);
    println!("Normal polynomial: {:?}", normal_poly);
}
