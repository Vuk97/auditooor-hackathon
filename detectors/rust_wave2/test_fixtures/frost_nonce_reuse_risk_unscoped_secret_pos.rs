// POSITIVE fixture — frost_nonce_reuse_risk_unscoped_secret
// A sign() function that takes &SigningNonces without any freshness guard.
// The detector SHOULD fire on this file.

pub struct SigningNonces {
    pub hiding: u64,
    pub binding: u64,
}

pub struct KeyPackage {
    pub min_signers: u32,
}

pub struct SigningPackage {
    pub message: Vec<u8>,
}

pub struct SignatureShare {
    pub value: u64,
}

pub type Error = String;

// VULN: consumes &SigningNonces without is_fresh() / mark_used() check.
pub fn sign(
    signing_package: &SigningPackage,
    signer_nonces: &SigningNonces,
    key_package: &KeyPackage,
) -> Result<SignatureShare, Error> {
    // compute binding factor from commitments
    let binding = signer_nonces.binding;
    let hiding = signer_nonces.hiding;

    // mix nonces into signature share (simplified)
    let share = hiding ^ binding ^ signing_package.message.len() as u64;

    Ok(SignatureShare { value: share })
}

// A second function that stores nonces in a struct without freshness tracking.
pub fn prepare_nonces(secret: u64) -> SigningNonces {
    let hiding = secret ^ 0xDEAD;
    let binding = secret ^ 0xBEEF;
    SigningNonces { hiding, binding }
}
