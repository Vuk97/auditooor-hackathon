// CLEAN fixture: nullifier is redacted before logging — detector must NOT fire
use std::collections::HashMap;

struct RedactedNullifier<'a>(&'a [u8; 32]);

impl<'a> std::fmt::Debug for RedactedNullifier<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted nullifier>")
    }
}

fn add_nullifier_to_chain(
    chain_nullifiers: &mut HashMap<[u8; 32], u64>,
    nullifier: &[u8; 32],
    tx_id: u64,
) -> Result<(), String> {
    // Guard present: value is wrapped in a redacting adapter before logging
    let redact_nullifier = RedactedNullifier(nullifier);
    trace!(?redact_nullifier, "adding nullifier to chain");

    if chain_nullifiers.insert(*nullifier, tx_id).is_some() {
        return Err("duplicate nullifier".to_string());
    }
    Ok(())
}

fn remove_from_chain(
    chain_nullifiers: &mut HashMap<[u8; 32], u64>,
    nullifier: &[u8; 32],
) {
    // Only logs a string literal, not the actual nullifier value
    trace!("removing nullifier from chain");
    chain_nullifiers.remove(nullifier);
}
