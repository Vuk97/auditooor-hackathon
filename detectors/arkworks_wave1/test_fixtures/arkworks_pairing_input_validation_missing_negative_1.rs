// Negative fixture 1: is_on_curve check present before pairing — no finding.
use ark_ec::{PairingEngine, AffineCurve};
use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};

fn safe_verify(a: G1Affine, b: G2Affine) -> bool {
    // Properly validate inputs before pairing.
    assert!(a.is_on_curve() && a.is_in_correct_subgroup_assuming_on_curve());
    assert!(b.is_on_curve() && b.is_in_correct_subgroup_assuming_on_curve());
    let result = Bls12_381::pairing(a, b);
    result != <Bls12_381 as PairingEngine>::Fqk::one()
}
