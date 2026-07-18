// NEGATIVE fixture — frost_keypackage_serialization_unauthenticated
// A function that deserializes a KeyPackage AND verifies the pubkey-package
// digest before using it — safe pattern.
// The detector MUST NOT fire on this file.

pub struct KeyPackage {
    pub identifier: u64,
    pub signing_share: [u8; 32],
    pub min_signers: u32,
}

pub struct PublicKeyPackage {
    pub group_public_key: [u8; 32],
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

pub fn verify_pubkey_package_digest(
    kp: &KeyPackage,
    expected_digest: &[u8; 32],
) -> Result<(), String> {
    // In production this would compute a cryptographic binding between
    // the key package and the public key package and compare to expected.
    let computed = [kp.identifier as u8; 32];
    if &computed != expected_digest {
        return Err("key package digest mismatch — possible key-rotation replay".into());
    }
    Ok(())
}

// SAFE: deserializes KeyPackage then verifies the pubkey-package digest.
pub fn load_key_package(
    buf: &[u8],
    expected_digest: &[u8; 32],
) -> Result<KeyPackage, String> {
    let kp: KeyPackage = KeyPackage::deserialize(buf)?;
    verify_pubkey_package_digest(&kp, expected_digest)?;
    Ok(kp)
}
