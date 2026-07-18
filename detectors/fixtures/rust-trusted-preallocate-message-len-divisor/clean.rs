// clean.rs — should NOT fire: all max_allocation impls have a secondary cap
// (min() call) that narrows the formula result to a protocol constant.

use std::cmp::min;

pub const MAX_PROTOCOL_MESSAGE_LEN: usize = 2 * 1024 * 1024;
pub const MAX_BLOCK_BYTES: u64 = 2 * 1024 * 1024;
pub const MIN_ITEM_SIZE: u64 = 36;
pub const MAX_ITEMS_IN_MESSAGE: u64 = 50_000;
pub const MAX_ADDRS_IN_MESSAGE: u64 = 1_000;
pub const MIN_ADDR_SIZE: u64 = 30;

pub trait TrustedPreallocate {
    fn max_allocation() -> u64;
}

/// SAFE: formula result is capped by a secondary min().
pub struct SafeInvHash;
impl TrustedPreallocate for SafeInvHash {
    fn max_allocation() -> u64 {
        let formula = ((MAX_PROTOCOL_MESSAGE_LEN - 1) / MIN_ITEM_SIZE as usize) as u64;
        min(formula, MAX_ITEMS_IN_MESSAGE)
    }
}

/// SAFE: returns a pure constant, no divide formula.
pub struct SafeHeader;
impl TrustedPreallocate for SafeHeader {
    fn max_allocation() -> u64 {
        160
    }
}

/// SAFE: delegates entirely to another type (no divide formula in this body).
pub struct SafeWrapper;
impl TrustedPreallocate for SafeWrapper {
    fn max_allocation() -> u64 {
        SafeInvHash::max_allocation()
    }
}

/// SAFE: uses cmp::min to cap the block-bytes formula.
pub struct SafeAddr;
impl TrustedPreallocate for SafeAddr {
    fn max_allocation() -> u64 {
        let raw = (MAX_BLOCK_BYTES - 1) / MIN_ADDR_SIZE;
        min(raw, MAX_ADDRS_IN_MESSAGE)
    }
}
