// POSITIVE fixture — frost_keypackage_serialization_unauthenticated
// A function that deserializes a KeyPackage from bytes without verifying
// the pubkey-package digest.
// The detector SHOULD fire on this file.

pub struct KeyPackage {
    pub identifier: u64,
    pub signing_share: [u8; 32],
    pub min_signers: u32,
}

impl KeyPackage {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 44 {
            return Err("too short".into());
        }
        let mut share = [0u8; 32];
        share.copy_from_slice(&bytes[8..40]);
        Ok(KeyPackage {
            identifier: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            signing_share: share,
            min_signers: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
        })
    }
}

// VULN: loads a KeyPackage from untrusted bytes without verifying the
// pubkey-package digest — an attacker can swap in arbitrary signing material.
pub fn load_key_package(buf: &[u8]) -> Result<KeyPackage, String> {
    let kp: KeyPackage = KeyPackage::deserialize(buf)?;
    // ... use kp directly without digest verification
    Ok(kp)
}

// Another vulnerable pattern using a bincode-style call signature.
pub fn load_key_package_bincode(buf: &[u8]) -> Result<KeyPackage, String> {
    let key_package: KeyPackage = KeyPackage::deserialize(buf)?;
    Ok(key_package)
}
