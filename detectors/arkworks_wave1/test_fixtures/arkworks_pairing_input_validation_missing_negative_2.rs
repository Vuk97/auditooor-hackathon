// Negative fixture 2: not an Arkworks file — no ark_* imports.
fn compute_pair(a: u64, b: u64) -> u64 {
    // Plain multiplication, not a pairing operation.
    a * b
}
