// CLEAN fixture: should NOT fire (safe bounded patterns)
//
// Three safe TrustedPreallocate implementations:
//   1. Type-specific size divisor: (MAX_BLOCK_BYTES - 1) / OWN_ITEM_SIZE
//   2. Single-type delegation (same-sized type, no max() of two types)
//   3. min() of two types (conservative bound - NOT the bug pattern)

pub trait TrustedPreallocate {
    fn max_allocation() -> u64;
}

const MAX_BLOCK_BYTES: u64 = 2_000_000;

pub struct SpendPrefixInTransactionV5;
pub struct Action;
pub struct Signature;
pub struct Groth16ProofSafe([u8; 192]);

const PROOF_SIZE: u64 = 192;
const SPEND_PREFIX_SIZE: u64 = 948;
const ACTION_SIZE: u64 = 820;

// SAFE 1: uses own type's serialized size as the divisor
impl TrustedPreallocate for SpendPrefixInTransactionV5 {
    fn max_allocation() -> u64 {
        (MAX_BLOCK_BYTES - 1) / SPEND_PREFIX_SIZE
    }
}

// SAFE 2: delegates to a single type (Action), not max() of two
impl TrustedPreallocate for Signature {
    fn max_allocation() -> u64 {
        // Each signature must have a corresponding action.
        Action::max_allocation()
    }
}

impl TrustedPreallocate for Action {
    fn max_allocation() -> u64 {
        (MAX_BLOCK_BYTES - 1) / ACTION_SIZE
    }
}

// SAFE 3: proof bound computed from own size
impl TrustedPreallocate for Groth16ProofSafe {
    fn max_allocation() -> u64 {
        // Use the proof's own serialized size as the divisor.
        (MAX_BLOCK_BYTES - 1) / PROOF_SIZE
    }
}
