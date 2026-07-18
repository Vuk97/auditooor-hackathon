// POSITIVE fixture — frost_threshold_check_against_active_set_only
// A signing function that checks signers.len() >= self.threshold
// without deduplicating identifiers first.
// The detector SHOULD fire on this file.

pub struct Identifier(pub u64);
pub struct Signer {
    pub identifier: Identifier,
}
pub struct KeyPackage {
    pub threshold: u32,
}
pub type Error = String;

pub fn verify_signing_set(
    signers: &[Signer],
    key_package: &KeyPackage,
) -> Result<(), Error> {
    // VULN: uses raw signers.len() — duplicate identifiers bypass threshold.
    if signers.len() >= key_package.threshold as usize {
        return Ok(());
    }
    Err(format!(
        "not enough signers: have {}, need {}",
        signers.len(),
        key_package.threshold
    ))
}

pub fn create_signing_package(
    signers: &[Signer],
    threshold: u32,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    // VULN: raw count threshold check against threshold field.
    if signers.len() >= threshold as usize {
        let mut pkg = message.to_vec();
        pkg.extend_from_slice(&threshold.to_le_bytes());
        return Ok(pkg);
    }
    Err("insufficient signers".into())
}
