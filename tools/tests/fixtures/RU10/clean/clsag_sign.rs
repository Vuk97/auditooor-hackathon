// RU10 clean fixture - a crypto sign fn generic over RngCore WITH the
// `+ CryptoRng` bound (the secure control). The caller cannot supply a
// low-entropy RNG, so the per-signature nonce scalar is unpredictable.
// RU10 must stay silent. Mirrors monero-oxide
// ringct/clsag/src/lib.rs::sign_core (the mutation target: dropping
// `+ CryptoRng` is the behavior-changing weakening).
use rand_core::{RngCore, CryptoRng};

fn sign_core<R: RngCore + CryptoRng>(rng: &mut R, ring_len: usize) -> Vec<Scalar> {
    let mut s = Vec::with_capacity(ring_len);
    for _ in 0..ring_len {
        s.push(Scalar::random(rng));
    }
    s
}
