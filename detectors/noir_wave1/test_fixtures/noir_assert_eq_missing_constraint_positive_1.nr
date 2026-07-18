// Positive fixture: assert_eq! inside an unconstrained fn.
// The equality check is a runtime assertion only — NOT a ZK constraint.
use dep::std;

unconstrained fn validate_and_decompose(x: Field) -> [u8; 32] {
    let bytes = x.to_le_bytes(32);
    // BUG: assert_eq! here is NOT a circuit constraint — it's a runtime check only.
    // The circuit does not enforce that bytes correctly represent x.
    assert_eq!(bytes.len(), 32);
    bytes
}

fn main(x: pub Field) -> pub [u8; 32] {
    validate_and_decompose(x)
}
