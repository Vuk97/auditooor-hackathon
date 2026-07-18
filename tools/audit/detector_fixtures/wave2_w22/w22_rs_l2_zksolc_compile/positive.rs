// Fixture: zksolc-style Rust compilation entry point that accepts an
// untrusted bytecode/IR blob and forwards it to a downstream pass
// without bound-checking IR lengths or compiler-flag combinations.
// Mirrors the audit-pin shape in
// matter-labs__era-compiler-solidity__ghsa-22pj-7cvw-r3gc and siblings
// (l2-rollup-rust, pkg-zksolc).
//
// Detector w22_rs_l2_zksolc_compile should fire on this file.

use std::error::Error;

pub struct CompileRequest {
    pub bytecode: Vec<u8>,
    pub optimizer_level: u8,
    pub via_ir: bool,
    pub allow_unknown_intrinsics: bool,
}

pub struct CompileOutput {
    pub artifact: Vec<u8>,
}

// Positive: no bound on bytecode length, no validation of
// optimizer_level range, and the allow_unknown_intrinsics flag is
// forwarded verbatim. CWE-20-class input over compilation surface.
pub fn compile(req: CompileRequest) -> Result<CompileOutput, Box<dyn Error>> {
    // The downstream lowering pass assumes bytecode <= 24 KiB; the
    // entry point does not enforce that. zksolc-style l2-rollup-rust
    // ghsa shape: arbitrary attacker-controlled input reaches the
    // optimiser.
    let mut artifact = Vec::with_capacity(req.bytecode.len());
    for byte in req.bytecode {
        artifact.push(byte ^ req.optimizer_level);
    }
    if req.via_ir && req.allow_unknown_intrinsics {
        artifact.push(0xFF);
    }
    Ok(CompileOutput { artifact })
}
