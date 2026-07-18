use std::collections::HashMap;

#[derive(Clone, Debug)]
struct Request {
    market: u64,
    amount: u64,
}

struct Engine {
    pending_by_batch: HashMap<u64, Vec<Request>>,
    available_inventory: HashMap<u64, u64>,
}

impl Engine {
    fn new() -> Self {
        Self {
            pending_by_batch: HashMap::new(),
            available_inventory: HashMap::new(),
        }
    }

    fn set_inventory(&mut self, market: u64, amount: u64) {
        self.available_inventory.insert(market, amount);
    }

    fn add_request(&mut self, batch_id: u64, request: Request) {
        self.pending_by_batch.entry(batch_id).or_default().push(request);
    }

    fn get_inventory(&self, market: u64) -> u64 {
        self.available_inventory.get(&market).copied().unwrap_or(0)
    }

    fn get_total_pending_amount(&self, market: u64) -> u64 {
        let mut total_needed = 0u64;
        for requests in self.pending_by_batch.values() {
            for request in requests {
                if request.market == market {
                    total_needed = total_needed.saturating_add(request.amount);
                }
            }
        }
        total_needed
    }

    fn validate_request(&self, request: &Request, market: u64) -> Result<(), String> {
        let total_needed = self.get_total_pending_amount(market);
        let available_inventory = self.get_inventory(market);

        if available_inventory < total_needed {
            return Err(format!(
                "inventory {} is insufficient for total pending {}",
                available_inventory, total_needed
            ));
        }

        if request.amount == 0 {
            return Err("request amount must be non-zero".to_string());
        }

        Ok(())
    }

    fn execute_request(&self, batch_id: u64, request_index: usize, market: u64) -> Result<u64, String> {
        let requests = self.pending_by_batch.get(&batch_id).ok_or("missing batch")?;
        let request = requests.get(request_index).ok_or("missing request")?;

        self.validate_request(request, market)?;

        let total_needed = self.get_total_pending_amount(market);
        let available_inventory = self.get_inventory(market);
        if available_inventory < total_needed {
            return Err("inventory insufficient for all pending requests".to_string());
        }

        Ok(request.amount)
    }
}

fn main() {
    let mut engine = Engine::new();
    engine.set_inventory(7, 100);

    engine.add_request(1, Request { market: 7, amount: 40 });
    engine.add_request(2, Request { market: 7, amount: 80 });

    let result = engine.execute_request(1, 0, 7);
    assert!(result.is_err());
}
