// Fixture: zksolc-style Rust compilation entry point that DOES enforce
// input bounds and rejects the dangerous flag combination upfront.
// Structurally similar to positive.rs but should NOT fire the
// w22_rs_l2_zksolc_compile detector.

use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct ValidationError(&'static str);

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for ValidationError {}

pub struct CompileRequest {
    pub bytecode: Vec<u8>,
    pub optimizer_level: u8,
    pub via_ir: bool,
    pub allow_unknown_intrinsics: bool,
}

pub struct CompileOutput {
    pub artifact: Vec<u8>,
}

const MAX_BYTECODE_LEN: usize = 24 * 1024;
const MAX_OPTIMIZER_LEVEL: u8 = 3;

// Negative: validates length, optimiser-level range, and rejects the
// dangerous via_ir + allow_unknown_intrinsics combination.
pub fn compile(req: CompileRequest) -> Result<CompileOutput, Box<dyn Error>> {
    if req.bytecode.len() > MAX_BYTECODE_LEN {
        return Err(Box::new(ValidationError("bytecode exceeds cap")));
    }
    if req.optimizer_level > MAX_OPTIMIZER_LEVEL {
        return Err(Box::new(ValidationError("optimizer level out of range")));
    }
    if req.via_ir && req.allow_unknown_intrinsics {
        return Err(Box::new(ValidationError(
            "via_ir + allow_unknown_intrinsics disallowed",
        )));
    }
    let mut artifact = Vec::with_capacity(req.bytecode.len());
    for byte in req.bytecode {
        artifact.push(byte ^ req.optimizer_level);
    }
    Ok(CompileOutput { artifact })
}
