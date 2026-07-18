use std::collections::HashMap;

#[derive(Clone, Debug)]
struct Request {
    request_id: u64,
    market: u64,
    amount: u64,
}

struct Engine {
    pending_by_batch: HashMap<u64, Vec<Request>>,
    request_reservations: HashMap<u64, u64>,
}

impl Engine {
    fn new() -> Self {
        Self {
            pending_by_batch: HashMap::new(),
            request_reservations: HashMap::new(),
        }
    }

    fn add_request(&mut self, batch_id: u64, request: Request) {
        self.pending_by_batch.entry(batch_id).or_default().push(request);
    }

    fn reserve_for_request(&mut self, request_id: u64, amount: u64) {
        self.request_reservations.insert(request_id, amount);
    }

    fn reserved_for_request(&self, request_id: u64) -> u64 {
        self.request_reservations.get(&request_id).copied().unwrap_or(0)
    }

    fn validate_request(&self, request: &Request) -> Result<(), String> {
        let reserved_for_request = self.reserved_for_request(request.request_id);
        if reserved_for_request < request.amount {
            return Err("request reservation is insufficient".to_string());
        }
        if request.market == 0 {
            return Err("invalid market".to_string());
        }
        Ok(())
    }

    fn execute_request(&self, batch_id: u64, request_index: usize) -> Result<u64, String> {
        let requests = self.pending_by_batch.get(&batch_id).ok_or("missing batch")?;
        let request = requests.get(request_index).ok_or("missing request")?;
        self.validate_request(request)?;
        Ok(request.amount)
    }
}

fn main() {
    let mut engine = Engine::new();
    engine.add_request(1, Request {
        request_id: 11,
        market: 7,
        amount: 40,
    });
    engine.reserve_for_request(11, 40);

    let result = engine.execute_request(1, 0);
    assert!(result.is_ok());
}
