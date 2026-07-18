// Post-fix shape: Coinbase PR 19775 (Cantina 3.1.1 fix).
// Trace extension only fires when claimed L2 block number EQUALS safe head number.

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

pub fn run_native_client(boot: BootInfo, safe_head: SafeHead) -> Result<()> {
    if boot.claimed_l2_block_number < safe_head.number {
        return Err(FaultProofProgramError::InvalidClaim(
            boot.agreed_l2_output_root,
            boot.claimed_l2_output_root,
        ));
    }

    // FIX: trace-extension only when targeting exactly the safe-head block.
    if boot.claimed_l2_block_number == safe_head.number {
        if boot.agreed_l2_output_root == boot.claimed_l2_output_root {
            return Ok(());
        }
        return Err(FaultProofProgramError::InvalidClaim(
            boot.agreed_l2_output_root,
            boot.claimed_l2_output_root,
        ));
    }

    Ok(())
}
