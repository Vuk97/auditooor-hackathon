// Pattern 2 — POSITIVE fixture for
//   rust.frost.aggregate.under_threshold_signature_shares
//
// `aggregate` accepts a signature_shares map and dispatches straight to
// the aggregation core without enforcing min_signers / threshold. An
// adversary supplying fewer than t shares can still produce a "valid"
// signature blob that downstream consumers will accept, because no
// length/threshold guard ever rejects under-threshold input.
//
// Mirrors the bug class fixed by `ff5ec8d` in lightsparkdev/frost.

use std::collections::BTreeMap;

pub struct Identifier(u16);
pub struct SignatureShare(Vec<u8>);
pub struct Signature(Vec<u8>);
pub struct SigningPackage {
    pub message: Vec<u8>,
}
pub struct PublicKeyPackage {
    pub group_pubkey: Vec<u8>,
}

pub struct AggregateError;

fn compute_aggregation_core(
    _msg: &[u8],
    _shares: &BTreeMap<Identifier, SignatureShare>,
) -> Vec<u8> {
    Vec::new()
}

// BUG: no min_signers / threshold check. signature_shares can have any size.
pub fn aggregate(
    signing_package: &SigningPackage,
    signature_shares: &BTreeMap<Identifier, SignatureShare>,
    pubkey_package: &PublicKeyPackage,
) -> Result<Signature, AggregateError> {
    let bytes = compute_aggregation_core(&signing_package.message, signature_shares);
    let _ = pubkey_package.group_pubkey.clone();
    Ok(Signature(bytes))
}
