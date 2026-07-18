use std::collections::HashMap;

pub struct LayerZeroEndpoint {
    failed_messages: HashMap<(u16, u64), Vec<u8>>,
    max_payload_size: usize,
    max_storage_per_channel: usize,
}

impl LayerZeroEndpoint {
    pub fn new() -> Self {
        Self {
            failed_messages: HashMap::new(),
            max_payload_size: 1024,
            max_storage_per_channel: 8192,
        }
    }

    pub fn lz_receive(
        &mut self,
        src_chain_id: u16,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), &'static str> {
        // Pre-check: reject oversized payloads before any storage
        if payload.len() > self.max_payload_size {
            return Err("payload too large");
        }

        // Execute business logic first
        let result = self.process_message(src_chain_id, nonce, &payload);

        // On failure, store only a fixed-size hash, not the full payload
        if result.is_err() {
            let payload_hash = Self::hash_payload(&payload);
            // Fixed-size storage, gas cost is constant
            self.failed_messages.insert(
                (src_chain_id, nonce),
                payload_hash.to_vec(),
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
        if payload.is_empty() {
            return Err("empty payload");
        }
        Ok(())
    }

    fn hash_payload(payload: &[u8]) -> [u8; 32] {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        payload.hash(&mut hasher);
        let hash = hasher.finish();
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&hash.to_le_bytes());
        result
    }
}

fn main() {
    let mut endpoint = LayerZeroEndpoint::new();
    let payload = vec![1u8; 512];
    let _ = endpoint.lz_receive(1, 100, payload);
}