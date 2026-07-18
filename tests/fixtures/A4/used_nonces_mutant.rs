// A4 fixture: MUTANT of used_nonces_clean.rs - the per-key guard is stripped.
// The bare `.replace(true)` discards the old-value return, so a replayed nonce
// is silently accepted (no uniqueness enforcement) -> MUST fire.
pub fn use_nonce(nonce: u64, used_nonces: &mut UsedNonces) -> Result<()> {
    let mut nonce_slot = used_nonces
        .used
        .get_mut((nonce % USED_NONCES_PER_ACCOUNT) as usize)
        .expect("nonce index out of bounds");
    nonce_slot.replace(true);
    Ok(())
}
