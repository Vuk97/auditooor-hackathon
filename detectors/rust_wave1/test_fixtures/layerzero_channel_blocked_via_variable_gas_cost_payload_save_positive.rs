use std::collections::HashMap;

pub struct LayerZeroEndpoint {
    // VULNERABLE: stores full payload, gas cost grows with payload size
    failed_messages: HashMap<(u16, u64), Vec<u8>>,
}

impl LayerZeroEndpoint {
    pub fn new() -> Self {
        Self {
            failed_messages: HashMap::new(),
        }
    }

    pub fn lz_receive(
        &mut self,
        src_chain_id: u16,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), &'static str> {
        // Execute business logic
        let result = self.process_message(src_chain_id, nonce, &payload);

        // VULNERABLE: on failure, stores the ENTIRE payload in dynamic mapping
        // Gas cost of this insert grows linearly with payload.len()
        // Attacker can send huge payload to consume all gas, blocking channel
        if result.is_err() {
            self.failed_messages.insert(
                (src_chain_id, nonce),
                payload, // full payload stored, variable gas cost
            );
        }

        result
    }

    fn process_message(
        &self,
        _src_chain_id: u16,
        _nonce: u64,
        payload: &[u8],
    ) -> Result<(), &'static str> {
        // Simulate some failure condition
        if payload.len() > 100 {
            return Err("message processing failed");
        }
        Ok(())
    }
}

fn main() {
    let mut endpoint = LayerZeroEndpoint::new();
    // Attacker sends large payload that will fail and trigger storage
    let malicious_payload = vec![0u8; 100_000];
    let _ = endpoint.lz_receive(1, 100, malicious_payload);
}