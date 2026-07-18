// NEGATIVE fixture — frost_nonce_reuse_risk_unscoped_secret
// A sign() function that takes &SigningNonces WITH a freshness guard.
// The detector MUST NOT fire on this file.

pub struct SigningNonces {
    pub hiding: u64,
    pub binding: u64,
    pub used: bool,
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

// SAFE: checks that the nonce hasn't been marked as used before proceeding.
pub fn sign(
    signing_package: &SigningPackage,
    signer_nonces: &mut SigningNonces,
    key_package: &KeyPackage,
) -> Result<SignatureShare, Error> {
    // Freshness guard — detect nonce reuse.
    if signer_nonces.used = true {
        return Err("nonce reuse detected: SigningNonces marked used".into());
    }

    let binding = signer_nonces.binding;
    let hiding = signer_nonces.hiding;

    // mark_used prevents re-use of this nonce.
    mark_used(signer_nonces);

    let share = hiding ^ binding ^ signing_package.message.len() as u64;
    Ok(SignatureShare { value: share })
}

pub fn mark_used(nonces: &mut SigningNonces) {
    nonces.used = true;
}
