// A4 fixture: GUARDED per-key uniqueness write (distilled from near-intents
// used_nonces.rs:104). The `.replace(true)` boolean return is consumed by a
// negated require! (check-and-set) -> a dominating per-key guard is PRESENT ->
// must NOT fire.
pub fn use_nonce(nonce: u64, used_nonces: &mut UsedNonces) -> Result<()> {
    let mut nonce_slot = used_nonces
        .used
        .get_mut((nonce % USED_NONCES_PER_ACCOUNT) as usize)
        .expect("nonce index out of bounds");
    require!(!nonce_slot.replace(true), ErrorCode::NonceAlreadyUsed);
    Ok(())
}
