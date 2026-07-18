// Positive fixture 1: E::pairing called without is_on_curve check.
use ark_ec::{PairingEngine, AffineCurve};
use ark_bls12_381::{Bls12_381, G1Affine, G2Affine, Fr};

fn verify_snark_proof(
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
    vk_alpha: G1Affine,
    vk_beta: G2Affine,
) -> bool {
    // BUG: no is_on_curve / check() call on a, b, c before pairing.
    let lhs = Bls12_381::pairing(a, b);
    let rhs = Bls12_381::pairing(vk_alpha, vk_beta);
    lhs == rhs
}
