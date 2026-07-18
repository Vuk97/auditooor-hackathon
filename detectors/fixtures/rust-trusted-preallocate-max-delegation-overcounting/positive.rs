// POSITIVE fixture: should fire (max-delegation overcounting pattern)
//
// Groth16Proof::max_allocation() delegates to max(SpendPrefix::max_allocation(),
// OutputPrefix::max_allocation()) with a TODO comment acknowledging the problem.
// The delegating type (Groth16Proof, 192 bytes) is smaller than the types whose
// bounds it inherits, so the pre-allocation ceiling is over-counted.

use std::cmp::max;

pub trait TrustedPreallocate {
    fn max_allocation() -> u64;
}

pub struct SpendPrefixInTransactionV5;
pub struct OutputPrefixInTransactionV5;
pub struct Groth16Proof([u8; 192]);

impl TrustedPreallocate for SpendPrefixInTransactionV5 {
    fn max_allocation() -> u64 {
        const MAX_BLOCK_BYTES: u64 = 2_000_000;
        const SHARED_ANCHOR_SPEND_SIZE: u64 = 948;
        (MAX_BLOCK_BYTES - 1) / SHARED_ANCHOR_SPEND_SIZE
    }
}

impl TrustedPreallocate for OutputPrefixInTransactionV5 {
    fn max_allocation() -> u64 {
        const MAX_BLOCK_BYTES: u64 = 2_000_000;
        const OUTPUT_SIZE: u64 = 756;
        (MAX_BLOCK_BYTES - 1) / OUTPUT_SIZE
    }
}

// BUG: delegates to max() of two sibling types without Groth16Proof's own size
impl TrustedPreallocate for Groth16Proof {
    fn max_allocation() -> u64 {
        // Each V5 transaction proof array entry must have a corresponding
        // spend or output prefix. We use the larger limit, so we don't reject
        // any valid large blocks.
        //
        // TODO: put a separate limit on proofs in spends and outputs
        max(
            SpendPrefixInTransactionV5::max_allocation(),
            OutputPrefixInTransactionV5::max_allocation(),
        )
    }
}
