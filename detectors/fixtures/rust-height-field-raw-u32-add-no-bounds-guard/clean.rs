// clean.rs - should NOT fire: safe/guarded Height construction variants.
//
// Case A: checked_add guard present -> no hit.
// Case B: saturating_add -> no hit.
// Case C: only small literal addend (1) -> not the bug class, skip.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Height(pub u32);

/// Safe: uses checked_add and propagates None as an error.
fn safe_checked_add(base: Height, max_len: u32) -> Option<(Height, Height)> {
    let start = Height(base.0.checked_add(1)?);
    let end = Height(base.0.checked_add(max_len)?);
    Some((start, end))
}

/// Safe: uses saturating_add (intentionally clamped, developer is aware).
fn safe_saturating(base: Height, delta: u32) -> Height {
    Height(base.0.saturating_add(delta))
}

/// Safe: addend is a small literal constant (not peer-supplied).
fn next_height(base: Height) -> Height {
    // +1 is the common "advance by one block" pattern, not the bug class.
    Height(base.0 + 1)
}

/// Safe: explicit MAX guard before the addition.
fn bounded_add(base: Height, delta: u32) -> Option<Height> {
    if base.0 > u32::MAX - delta {
        return None;
    }
    Some(Height(base.0 + delta))
}
