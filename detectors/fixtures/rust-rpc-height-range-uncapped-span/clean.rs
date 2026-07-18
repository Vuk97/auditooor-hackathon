// clean.rs - should NOT fire: span cap guard present
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

const MAX_BLOCK_RANGE: u32 = 1000;

// Safe variant: checks (end - start) against MAX_BLOCK_RANGE before returning.
fn build_height_range(
    start: Option<u32>,
    end: Option<u32>,
    chain_height: Height,
) -> Result<RangeInclusive<Height>> {
    let start = Height(start.unwrap_or(0)).min(chain_height);

    let end = match end {
        Some(0) | None => chain_height,
        Some(val) => Height(val).min(chain_height),
    };

    // Span-cap guard: reject requests that span more than MAX_BLOCK_RANGE blocks
    if end.0 - start.0 > MAX_BLOCK_RANGE {
        return Err(Error);
    }

    if start > end {
        return Err(Error);
    }

    Ok(start..=end)
}
