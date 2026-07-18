// CLEAN fixture — should NOT fire: async RPC handler checks span cap before
// issuing the state range-scan.

const MAX_BLOCK_RANGE: u32 = 1000;

struct MyRequest {
    start: Option<u32>,
    end: Option<u32>,
    addresses: Vec<String>,
}

struct ReadState;
impl ReadState {
    async fn call(&self, _req: StateRequest) -> Result<Vec<String>, String> { Ok(vec![]) }
}

enum StateRequest {
    TransactionIdsByAddresses { addresses: Vec<String>, height_range: std::ops::RangeInclusive<u32> },
}

struct MyRpc {
    read_state: ReadState,
}

impl MyRpc {
    async fn get_address_tx_ids(&self, request: MyRequest) -> Result<Vec<String>, String> {
        let start = request.start.unwrap_or(0);
        let end = request.end.unwrap_or(start);

        // Span-cap guard — detector must see this and skip the flag.
        if end - start > MAX_BLOCK_RANGE {
            return Err("range too large".to_string());
        }

        let height_range = start..=end;
        let req = StateRequest::TransactionIdsByAddresses {
            addresses: request.addresses,
            height_range,
        };
        self.read_state.call(req).await
    }
}
