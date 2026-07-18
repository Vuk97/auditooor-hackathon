// Positive fixture 2: miller_loop called without on-curve validation.
use ark_ec::{PairingEngine, AffineCurve};
use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};

fn compute_miller(p: G1Affine, q: G2Affine) -> <Bls12_381 as PairingEngine>::Fqk {
    // Missing: p.check() and q.check() before miller_loop.
    let p_prep = <Bls12_381 as PairingEngine>::G1Prepared::from(p);
    let q_prep = <Bls12_381 as PairingEngine>::G2Prepared::from(q);
    Bls12_381::miller_loop([(&p_prep, &q_prep)].iter())
}
