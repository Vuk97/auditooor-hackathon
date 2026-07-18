// Vuln fixture for `reth-opcode-dispatch-missing-cancun-prague`.
//
// `step` does NOT include the Cancun blob opcodes (BLOBHASH 0x49 /
// BLOBBASEFEE 0x4a). Cancun-era contracts that call them will
// hit the InvalidOpcode arm and the client forks off canonical.
#![allow(dead_code)]

pub enum StepResult {
    Continue,
    Stop,
    InvalidOpcode,
}

pub fn step(opcode: u8) -> StepResult {
    match opcode {
        0x00 => StepResult::Stop,
        0x01 => StepResult::Continue,
        0x02 => StepResult::Continue,
        0x40 => StepResult::Continue,
        0x47 => StepResult::Continue,
        0x48 => StepResult::Continue,
        // BUG: missing 0x49 (BLOBHASH) and 0x4a (BLOBBASEFEE).
        _ => StepResult::InvalidOpcode,
    }
}
