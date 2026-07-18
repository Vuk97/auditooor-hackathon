// positive.rs - SHOULD fire: build_height_range with tip-default but no span cap
use std::ops::RangeInclusive;

#[derive(Clone, Copy, PartialEq, PartialOrd)]
struct Height(pub u32);

impl Height {
    fn min(self, other: Height) -> Height {
        if self.0 < other.0 { self } else { other }
    }
}

struct Error;
type Result<T> = std::result::Result<T, Error>;

// This function silently defaults end=None/0 to chain_height and returns the
// full range with no span-width cap. Should fire.
fn build_height_range(
    start: Option<u32>,
    end: Option<u32>,
    chain_height: Height,
) -> Result<RangeInclusive<Height>> {
    let start = Height(start.unwrap_or(0)).min(chain_height);

    // Tip-default arm: missing or zero end => chain tip (unbounded span)
    let end = match end {
        Some(0) | None => chain_height,
        Some(val) => Height(val).min(chain_height),
    };

    if start > end {
        return Err(Error);
    }

    // No span-cap guard here: attacker sets start=0, end=None => full chain scan
    Ok(start..=end)
}
