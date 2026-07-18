// A4 fixture: FP-guard case. Uniqueness is STRUCTURAL - the key `used_slot` is
// an internal monotone counter incremented in the same body, so there is no
// attacker-chosen replayable key. Must be SUPPRESSED (fp_suppressed), NOT fired.
pub fn register_next(processed: &mut Vec<u64>, used_slot: &mut u64) -> Result<()> {
    processed.push(*used_slot);
    *used_slot += 1;
    Ok(())
}
