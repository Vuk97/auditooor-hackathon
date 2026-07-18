// positive.rs - SHOULD fire: raw u32 addition on Height inner field
// with a variable addend and no overflow guard.
//
// Mirrors the real zebra pattern in find_chain_height_range:
//   Height(intersection_height.0 + max_len)  -- max_len is a u32 parameter

use std::ops::RangeBounds;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Height(pub u32);

/// Returns the start and end heights for a block-range response.
/// VULNERABLE: both Height constructions use raw u32 addition.
/// If intersection_height.0 is near u32::MAX and max_len > 0,
/// max_height wraps below start_height yielding an empty range.
fn find_chain_height_range(
    intersection_height: Option<Height>,
    max_len: u32,
) -> (Height, Height) {
    match intersection_height {
        Some(intersection_height) => (
            // Adding 1 is the low-risk part but the pattern still matches
            // the vulnerable line below.
            Height(intersection_height.0 + 1),
            // VULNERABLE: max_len is caller-supplied with no guard.
            Height(intersection_height.0 + max_len),
        ),
        None => (Height(0), Height(max_len - 1)),
    }
}
