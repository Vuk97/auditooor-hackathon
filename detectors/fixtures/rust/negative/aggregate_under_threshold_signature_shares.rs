// Pattern 2 — NEGATIVE fixture for
//   rust.frost.aggregate.under_threshold_signature_shares
//
// `aggregate` enforces signature_shares.len() >= min_signers via an
// explicit length-check + ensure!() / Err return before dispatching to
// the aggregation core. Detector should NOT fire.

use std::collections::BTreeMap;

pub struct Identifier(u16);
pub struct SignatureShare(Vec<u8>);
pub struct Signature(Vec<u8>);
pub struct SigningPackage {
    pub message: Vec<u8>,
}
pub struct PublicKeyPackage {
    pub group_pubkey: Vec<u8>,
    pub min_signers: usize,
}

pub enum AggregateError {
    InvalidNumberOfShares,
}

fn compute_aggregation_core(
    _msg: &[u8],
    _shares: &BTreeMap<Identifier, SignatureShare>,
) -> Vec<u8> {
    Vec::new()
}

pub fn aggregate(
    signing_package: &SigningPackage,
    signature_shares: &BTreeMap<Identifier, SignatureShare>,
    pubkey_package: &PublicKeyPackage,
) -> Result<Signature, AggregateError> {
    // FIXED: enforce min_signers / threshold.
    if signature_shares.len() < pubkey_package.min_signers {
        return Err(AggregateError::InvalidNumberOfShares);
    }
    let bytes = compute_aggregation_core(&signing_package.message, signature_shares);
    Ok(Signature(bytes))
}
