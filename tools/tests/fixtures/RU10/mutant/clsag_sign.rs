// RU10 mutant fixture - the SAME crypto sign fn with the `+ CryptoRng` bound
// DROPPED (the behavior-changing mutation). The caller can now pass a
// deterministic / low-entropy RngCore, so the per-signature nonce scalar
// becomes predictable -> nonce reuse -> signing-key recovery. RU10 must FIRE
// exactly once at sign_core (arm=missing_cryptorng_bound). Mirrors
// monero-oxide ringct/clsag/src/lib.rs::sign_core with the entropy bound
// weakened.
use rand_core::RngCore;

fn sign_core<R: RngCore>(rng: &mut R, ring_len: usize) -> Vec<Scalar> {
    let mut s = Vec::with_capacity(ring_len);
    for _ in 0..ring_len {
        s.push(Scalar::random(rng));
    }
    s
}
