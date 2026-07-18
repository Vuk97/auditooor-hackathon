// Negative fixture 2: not a Plonky3 file — no p3_air or AirBuilder.
fn compute_lookup(values: &[u32], table: &[u32]) -> bool {
    for v in values {
        if !table.contains(v) {
            return false;
        }
    }
    true
}
