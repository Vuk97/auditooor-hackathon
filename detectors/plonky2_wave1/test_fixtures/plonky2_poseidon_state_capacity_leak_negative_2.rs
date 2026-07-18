// Negative fixture: not a Plonky2 file and no Poseidon usage.
// Should produce zero findings even with large array indexing.
pub fn matrix_multiply(a: &[[f64; 12]], b: &[[f64; 12]]) -> Vec<Vec<f64>> {
    let state = vec![0.0f64; 12];
    let val8 = state[8]; // index 8 but no Plonky2 / Poseidon context
    let val9 = state[9]; // index 9 but no Plonky2 / Poseidon context
    vec![vec![val8, val9]]
}
