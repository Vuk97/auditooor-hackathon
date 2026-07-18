// Clean fixture for `reth-opcode-dispatch-missing-cancun-prague`.
//
// `step` includes both BLOBHASH (0x49) and BLOBBASEFEE (0x4a). Detector
// must NOT fire because the body contains the negative-regex tokens.
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
        0x49 => StepResult::Continue, // BLOBHASH (EIP-4844)
        0x4a => StepResult::Continue, // BLOBBASEFEE (EIP-7516)
        _ => StepResult::InvalidOpcode,
    }
}
