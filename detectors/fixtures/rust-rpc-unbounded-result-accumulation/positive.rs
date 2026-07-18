// Positive fixture: RPC method that returns Vec<String> from an
// attacker-supplied address set with no result-count cap.
// The detector SHOULD fire on this.

use std::collections::BTreeMap;

struct ReadState;
struct Request { addresses: Vec<String>, start: u32, end: u32 }

async fn get_address_tx_ids(request: Request) -> Result<Vec<String>, String> {
    let valid_addresses = request.addresses;
    // Simulate iterating over all matching transaction IDs
    let hashes: BTreeMap<u64, String> = query_state(&valid_addresses);
    let result: Vec<String> = hashes
        .iter()
        .map(|(_loc, tx_id)| tx_id.clone())
        .collect();  // unbounded: no .take(n) or max_results guard
    Ok(result)
}

fn query_state(_addrs: &[String]) -> BTreeMap<u64, String> {
    BTreeMap::new()
}
