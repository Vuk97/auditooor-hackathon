use std::collections::HashMap;

/// Simulated LayerZero endpoint for cross-chain messaging
pub struct LayerZeroEndpoint {
    pub chain_id: u64,
    pub nonce_tracker: HashMap<(u64, u64), u64>, // (src_chain, nonce) -> count
}

/// Message packet from LayerZero
pub struct Packet {
    pub src_chain_id: u64,
    pub nonce: u64,
    pub payload: Vec<u8>,
    pub sender: [u8; 32],
}

/// VULNERABLE: Bridge contract with replay bypass
/// The _receive_message function is callable directly, bypassing access control
pub struct CrossChainBridge {
    endpoint: LayerZeroEndpoint,
    trusted_remote: [u8; 32],
    processed_nonces: HashMap<(u64, u64), bool>,
}

/// Error types for bridge operations
#[derive(Debug, PartialEq)]
pub enum BridgeError {
    UnauthorizedEndpoint,
    InvalidSender,
    MessageAlreadyProcessed,
    ReplayDetected,
}

impl CrossChainBridge {
    pub fn new(endpoint: LayerZeroEndpoint, trusted_remote: [u8; 32]) -> Self {
        Self {
            endpoint,
            trusted_remote,
            processed_nonces: HashMap::new(),
        }
    }

    /// GUARDED ENTRY POINT: Has access control but replay can bypass it
    pub fn lz_receive(
        &mut self,
        caller: [u8; 32],
        src_chain_id: u64,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), BridgeError> {
        // Access control: verify caller is the LayerZero endpoint
        if caller != self.endpoint_address() {
            return Err(BridgeError::UnauthorizedEndpoint);
        }

        // Replay protection: check nonce not already processed
        let nonce_key = (src_chain_id, nonce);
        if self.processed_nonces.get(&nonce_key).copied().unwrap_or(false) {
            return Err(BridgeError::MessageAlreadyProcessed);
        }

        self.processed_nonces.insert(nonce_key, true);

        // Delegates to internal handler
        self._receive_message(src_chain_id, nonce, payload)
    }

    /// VULNERABLE: Publicly callable, bypasses lz_receive access control!
    /// An attacker can replay messages by calling this directly,
    /// skipping the nonce check and endpoint verification in lz_receive
    pub fn _receive_message(
        &mut self,
        src_chain_id: u64,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), BridgeError> {
        // No access control here!
        // No replay protection here!
        // Attacker can replay same (src_chain_id, nonce, payload) indefinitely

        let action = self.decode_payload(&payload)?;
        self.execute_action(src_chain_id, nonce, action)
    }

    /// Alternative vulnerable path: explicit replay function that calls internal handler
    pub fn retry_failed_message(
        &mut self,
        src_chain_id: u64,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), BridgeError> {
        // Intentionally bypasses nonce check - "retry" functionality
        // This is the actual vulnerability pattern from the LayerZero audit:
        // when messages are replayed the contract calls _receiveMessage directly,
        // skipping the access-control modifier that normally guards the entry point
        self._receive_message(src_chain_id, nonce, payload)
    }

    fn endpoint_address(&self) -> [u8; 32] {
        [0xAB; 32]
    }

    fn decode_payload(&self, payload: &[u8]) -> Result<u8, BridgeError> {
        payload.first().copied().ok_or(BridgeError::InvalidSender)
    }

    fn execute_action(
        &mut self,
        _src_chain_id: u64,
        _nonce: u64,
        action: u8,
    ) -> Result<(), BridgeError> {
        match action {
            1 => Ok(()), // mint - can be replayed to mint infinite tokens!
            2 => Ok(()), // burn
            _ => Err(BridgeError::InvalidSender),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_exploit() {
        let endpoint = LayerZeroEndpoint {
            chain_id: 1,
            nonce_tracker: HashMap::new(),
        };
        let mut bridge = CrossChainBridge::new(endpoint, [0xCD; 32]);

        // Attacker calls _receive_message directly, bypassing lz_receive guards
        // Same message can be replayed multiple times
        assert!(bridge._receive_message(2, 100, vec![1]).is_ok());
        assert!(bridge._receive_message(2, 100, vec![1]).is_ok()); // REPLAY! Should fail but doesn't
        assert!(bridge._receive_message(2, 100, vec![1]).is_ok()); // REPLAY! Infinite mints

        // Also exploitable via retry_failed_message
        assert!(bridge.retry_failed_message(2, 100, vec![1]).is_ok());
    }
}