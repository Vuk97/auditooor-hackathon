// POSITIVE fixture: trace! emits raw nullifier — detector MUST fire
use std::collections::HashMap;

fn add_nullifier_to_chain(
    chain_nullifiers: &mut HashMap<[u8; 32], u64>,
    nullifier: &[u8; 32],
    tx_id: u64,
) -> Result<(), String> {
    // Directly logs the shielded nullifier value via ?nullifier debug specifier
    trace!(?nullifier, "adding nullifier to chain");

    if chain_nullifiers.insert(*nullifier, tx_id).is_some() {
        return Err("duplicate nullifier".to_string());
    }
    Ok(())
}

fn remove_from_chain(
    chain_nullifiers: &mut HashMap<[u8; 32], u64>,
    spending_key: &[u8; 32],
) {
    // Also fires on spending_key
    debug!(?spending_key, "removing spend record");
    chain_nullifiers.remove(spending_key);
}
