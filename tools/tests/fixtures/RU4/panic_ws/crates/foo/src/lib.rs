//! Bare-arith fixture: a usize underflow and a checked_add().unwrap().

pub fn last_index(v: &[u8]) -> usize {
    // Bare arith: wraps to usize::MAX in a wrap-silent release build.
    v.len() - 1
}

pub fn add_one(x: u64) -> u64 {
    // checked_add().unwrap() is NOT wrap-eligible (it panics, never wraps).
    x.checked_add(1).unwrap()
}
