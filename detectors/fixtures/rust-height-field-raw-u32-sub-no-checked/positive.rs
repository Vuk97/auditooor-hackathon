// positive.rs - SHOULD fire: raw u32 subtraction on Height.0 fields
// feeding depth/confirmations outputs, with no checked_sub or ordering guard.

#[derive(Copy, Clone, Debug)]
pub struct Height(pub u32);

pub fn tip_height_db() -> Option<Height> {
    Some(Height(100))
}

pub fn height_by_hash_db() -> Option<Height> {
    Some(Height(95))
}

// VULN 1: fn depth -- returns Option<u32>, uses tip.0 - height.0 directly
pub fn depth() -> Option<u32> {
    let tip = tip_height_db()?;
    let height = height_by_hash_db()?;
    // No ordering check: if height > tip after a reorg, this wraps to ~u32::MAX
    Some(tip.0 - height.0)
}

// VULN 2: confirmations with 1 + tip.0 - height.0
pub fn get_confirmations() -> Option<u64> {
    let tip = tip_height_db()?;
    let height = height_by_hash_db()?;
    let confirmations = 1 + tip.0 - height.0;
    Some(confirmations as u64)
}
