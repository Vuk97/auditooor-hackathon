// Negative fixture: assert_eq! inside a regular constrained fn — properly
// generates a ZK circuit constraint. No finding expected.
use dep::std;

fn verify_hash_preimage(preimage: Field, expected_hash: Field) {
    let computed = dep::std::hash::pedersen_hash([preimage]);
    // assert_eq! in a constrained fn — this IS a circuit constraint
    assert_eq!(computed[0], expected_hash);
}

fn main(preimage: pub Field, hash: pub Field) {
    verify_hash_preimage(preimage, hash);
}
