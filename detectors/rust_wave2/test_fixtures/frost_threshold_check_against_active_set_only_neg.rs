// NEGATIVE fixture — frost_threshold_check_against_active_set_only
// A signing function that deduplicates identifiers via HashSet before
// checking the threshold — safe pattern.
// The detector MUST NOT fire on this file.

use std::collections::HashSet;

pub struct Identifier(pub u64);

impl std::hash::Hash for Identifier {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl PartialEq for Identifier { fn eq(&self, other: &Self) -> bool { self.0 == other.0 } }
impl Eq for Identifier {}

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
    // SAFE: deduplicate identifiers first, then check the threshold.
    let unique_ids: HashSet<_> = signers.iter().map(|s| s.identifier.0).collect::<HashSet<_>>();
    if unique_ids.len() >= key_package.threshold as usize {
        return Ok(());
    }
    Err(format!(
        "not enough distinct signers: have {}, need {}",
        unique_ids.len(),
        key_package.threshold
    ))
}
