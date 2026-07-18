// POSITIVE fixture — SHOULD fire: async RPC handler reads start+end from
// request and issues a height-range state scan with no span cap.

struct MyRequest {
    start: Option<u32>,
    end: Option<u32>,
    addresses: Vec<String>,
}

struct ReadState;
impl ReadState {
    async fn call(&self, _req: StateRequest) -> Vec<String> { vec![] }
}

enum StateRequest {
    TransactionIdsByAddresses { addresses: Vec<String>, height_range: std::ops::RangeInclusive<u32> },
}

struct MyRpc {
    read_state: ReadState,
}

impl MyRpc {
    async fn get_address_tx_ids(&self, request: MyRequest) -> Vec<String> {
        // Build height range directly from caller-supplied fields — no cap.
        let start = request.start.unwrap_or(0);
        let end = request.end.unwrap_or(1_000_000);
        let height_range = start..=end;

        let req = StateRequest::TransactionIdsByAddresses {
            addresses: request.addresses,
            height_range,
        };
        self.read_state.call(req).await
    }
}
