// Reproduction shape of Cantina/Kona finding 3.1.1 (Critical).
// Source: kona/bin/client/src/single.rs#L70-L93 at commit 86910c9.
// PRE-FIX: trace-extension early-return fires whenever output roots match,
// without verifying the claimed L2 block number is the safe head.

#![allow(dead_code)]

pub struct BootInfo {
    pub agreed_l2_output_root: [u8; 32],
    pub claimed_l2_output_root: [u8; 32],
    pub claimed_l2_block_number: u64,
}

pub struct SafeHead {
    pub number: u64,
    pub output_root: [u8; 32],
}

#[derive(Debug)]
pub enum FaultProofProgramError {
    InvalidClaim([u8; 32], [u8; 32]),
}

pub type Result<T> = core::result::Result<T, FaultProofProgramError>;

/// run_native_client: pre-fix kona shape.
pub fn run_native_client(boot: BootInfo, safe_head: SafeHead) -> Result<()> {
    if boot.claimed_l2_block_number < safe_head.number {
        return Err(FaultProofProgramError::InvalidClaim(
            boot.agreed_l2_output_root,
            boot.claimed_l2_output_root,
        ));
    }

    // BUG: trace-extension fires only on output-root equality, no block-number gate.
    if boot.agreed_l2_output_root == boot.claimed_l2_output_root {
        // "Trace extension detected. State transition is already agreed upon."
        return Ok(());
    }

    // ... derivation + execution would follow ...
    Ok(())
}
