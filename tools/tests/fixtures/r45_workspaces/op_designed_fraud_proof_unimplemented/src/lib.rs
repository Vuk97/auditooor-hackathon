// ismp-optimism consensus client stub.
// FraudProofUnimplemented mirrors the real audit-pin state at
// modules/ismp/clients/ismp-optimism/src/lib.rs:256

use std::fmt;

#[derive(Debug)]
pub enum OptimismError {
    #[allow(dead_code)]
    InvalidProof,
    /// Fraud proof verification unimplemented
    FraudProofUnimplemented,
}

impl fmt::Display for OptimismError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptimismError::InvalidProof => write!(f, "invalid proof"),
            OptimismError::FraudProofUnimplemented => write!(f, "Fraud proof verification unimplemented"),
        }
    }
}

/// verify_fraud_proof returns FraudProofUnimplemented at the audit-pin tree.
/// The named defense-in-depth (fraud proofs / challenger) is NOT operational.
pub fn verify_fraud_proof(
    _output_root: [u8; 32],
    _proof: &[u8],
) -> Result<bool, OptimismError> {
    Err(OptimismError::FraudProofUnimplemented)
}

/// challenger function also returns Unimplemented
pub fn challenger_dispute(_output: [u8; 32]) -> Result<(), OptimismError> {
    Err(OptimismError::FraudProofUnimplemented)
}
