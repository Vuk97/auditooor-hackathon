// positive.rs — SHOULD fire: async RPC fn issues UtxosByAddresses query and
// accumulates all results into a Vec via for+push with no result-size cap.
use std::collections::HashSet;

struct ReadState;
struct UtxoEntry { address: String, value: u64 }
struct AddressUtxos { data: Vec<(String, u64)> }
impl AddressUtxos {
    fn utxos(&self) -> impl Iterator<Item=&(String, u64)> { self.data.iter() }
}

enum ReadRequest { UtxosByAddresses(HashSet<String>) }
enum ReadResponse { AddressUtxos(AddressUtxos) }

struct Request { addresses: Vec<String> }

impl ReadState {
    async fn call(&mut self, _req: ReadRequest) -> Result<ReadResponse, String> {
        Ok(ReadResponse::AddressUtxos(AddressUtxos { data: vec![] }))
    }
}

async fn get_address_utxos(
    mut read_state: ReadState,
    request: Request,
) -> Result<Vec<UtxoEntry>, String> {
    let valid_addresses: HashSet<String> = request.addresses.into_iter().collect();
    let req = ReadRequest::UtxosByAddresses(valid_addresses);
    let response = read_state.call(req).await?;
    let utxos = match response {
        ReadResponse::AddressUtxos(u) => u,
    };

    let mut response_utxos = vec![];
    for utxo_data in utxos.utxos() {
        let entry = UtxoEntry {
            address: utxo_data.0.clone(),
            value: utxo_data.1,
        };
        response_utxos.push(entry);
        // no length check, no cap, no break on size
    }

    Ok(response_utxos)
}
