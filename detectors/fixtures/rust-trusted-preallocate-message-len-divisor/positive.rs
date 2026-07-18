// positive.rs — SHOULD fire: max_allocation uses a size-limit / item-size
// divide formula as the SOLE bound with no secondary min() cap.

pub const MAX_PROTOCOL_MESSAGE_LEN: usize = 2 * 1024 * 1024; // 2 MiB
pub const MAX_BLOCK_BYTES: u64 = 2 * 1024 * 1024;
pub const MIN_ITEM_SIZE: u64 = 36;
pub const MIN_TX_SIZE: u64 = 41;
pub const MIN_JOINSPLIT_SIZE: u64 = 1802;

pub trait TrustedPreallocate {
    fn max_allocation() -> u64;
}

/// SHOULD FIRE: returns bare formula with no secondary min()
pub struct UncappedInvHash;
impl TrustedPreallocate for UncappedInvHash {
    fn max_allocation() -> u64 {
        // No secondary min() — sole bound from divide formula.
        ((MAX_PROTOCOL_MESSAGE_LEN - 1) / MIN_ITEM_SIZE as usize) as u64
    }
}

/// SHOULD FIRE: MAX_BLOCK_BYTES variant, sole bound.
pub struct UncappedTransaction;
impl TrustedPreallocate for UncappedTransaction {
    fn max_allocation() -> u64 {
        MAX_BLOCK_BYTES / MIN_TX_SIZE
    }
}

/// SHOULD FIRE: another block-bytes / size sole bound.
pub struct UncappedJoinSplit;
impl TrustedPreallocate for UncappedJoinSplit {
    fn max_allocation() -> u64 {
        (MAX_BLOCK_BYTES - 1) / MIN_JOINSPLIT_SIZE
    }
}
