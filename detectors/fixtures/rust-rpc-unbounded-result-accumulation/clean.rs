// Clean fixture: same shape but with a .take(n) cap — detector should NOT fire.

use std::collections::BTreeMap;

const MAX_TX_IDS: usize = 1000;

struct Request { addresses: Vec<String>, start: u32, end: u32 }

async fn get_address_tx_ids(request: Request) -> Result<Vec<String>, String> {
    let valid_addresses = request.addresses;
    let hashes: BTreeMap<u64, String> = query_state(&valid_addresses);
    // Guard: result count is capped before returning
    let result: Vec<String> = hashes
        .iter()
        .take(MAX_TX_IDS)      // <-- result-count cap present
        .map(|(_loc, tx_id)| tx_id.clone())
        .collect();
    Ok(result)
}

fn query_state(_addrs: &[String]) -> BTreeMap<u64, String> {
    BTreeMap::new()
}
