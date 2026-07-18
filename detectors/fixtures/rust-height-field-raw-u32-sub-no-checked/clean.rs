// clean.rs - should NOT fire: safe variants using checked_sub or ordering guards

#[derive(Copy, Clone, Debug)]
pub struct Height(pub u32);

pub fn tip_height_db() -> Option<Height> {
    Some(Height(100))
}

pub fn height_by_hash_db() -> Option<Height> {
    Some(Height(95))
}

// SAFE 1: checked_sub used
pub fn depth_checked() -> Option<u32> {
    let tip = tip_height_db()?;
    let height = height_by_hash_db()?;
    tip.0.checked_sub(height.0)
}

// SAFE 2: explicit ordering guard before subtraction
pub fn depth_guarded() -> Option<u32> {
    let tip = tip_height_db()?;
    let height = height_by_hash_db()?;
    if height.0 > tip.0 {
        return None;
    }
    Some(tip.0 - height.0)
}

// SAFE 3: saturating_sub
pub fn depth_saturating() -> Option<u32> {
    let tip = tip_height_db()?;
    let height = height_by_hash_db()?;
    Some(tip.0.saturating_sub(height.0))
}
