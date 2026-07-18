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

/// Access-controlled bridge contract with proper replay protection
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

    /// GUARDED ENTRY POINT: Only callable by verified LayerZero endpoint
    /// with proper access control and replay protection
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

        // Mark nonce as processed BEFORE calling internal handler
        self.processed_nonces.insert(nonce_key, true);

        // Now safe to process - replay of same nonce will fail above
        self._receive_message(src_chain_id, nonce, payload)
    }

    /// Internal message handler - INVARIANT: must only be called from lz_receive
    /// after access control and replay checks pass
    fn _receive_message(
        &mut self,
        src_chain_id: u64,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), BridgeError> {
        // Decode and execute cross-chain action
        let action = self.decode_payload(&payload)?;
        self.execute_action(src_chain_id, nonce, action)
    }

    fn endpoint_address(&self) -> [u8; 32] {
        // Simulated: in real code this would be the actual endpoint address
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
        // Execute based on action type
        match action {
            1 => Ok(()), // mint
            2 => Ok(()), // burn
            _ => Err(BridgeError::InvalidSender),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_blocked() {
        let endpoint = LayerZeroEndpoint {
            chain_id: 1,
            nonce_tracker: HashMap::new(),
        };
        let mut bridge = CrossChainBridge::new(endpoint, [0xCD; 32]);
        let caller = [0xAB; 32];

        // First call succeeds
        assert!(bridge.lz_receive(caller, 2, 100, vec![1]).is_ok());

        // Replay with same nonce fails
        assert_eq!(
            bridge.lz_receive(caller, 2, 100, vec![1]),
            Err(BridgeError::MessageAlreadyProcessed)
        );
    }
}