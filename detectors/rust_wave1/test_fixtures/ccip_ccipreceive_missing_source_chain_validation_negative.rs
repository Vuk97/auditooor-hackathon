use std::collections::HashSet;

/// Message from CCIP bridge
pub struct Any2EVMMessage {
    pub message_id: [u8; 32],
    pub source_chain_selector: u64,
    pub sender: [u8; 32],
    pub data: Vec<u8>,
    pub token_amounts: Vec<TokenAmount>,
}

pub struct TokenAmount {
    pub token: [u8; 32],
    pub amount: u128,
}

/// Bridge with proper source chain validation
pub struct BridgeCCIP {
    allowed_source_chains: HashSet<u64>,
    total_minted: u128,
}

impl BridgeCCIP {
    pub fn new(allowed_chains: Vec<u64>) -> Self {
        let mut allowed_source_chains = HashSet::new();
        for chain in allowed_chains {
            allowed_source_chains.insert(chain);
        }
        Self {
            allowed_source_chains,
            total_minted: 0,
        }
    }

    pub fn _ccip_receive(&mut self, message: Any2EVMMessage) -> Result<(), &'static str> {
        // Validate source chain is in allowlist
        if !self.allowed_source_chains.contains(&message.source_chain_selector) {
            return Err("Source chain not allowed");
        }

        // Process token amounts
        for token_amount in &message.token_amounts {
            self.total_minted = self.total_minted.saturating_add(token_amount.amount);
        }

        // Process message data
        let _ = message.data;

        Ok(())
    }
}

fn main() {
    let mut bridge = BridgeCCIP::new(vec![1u64, 2u64]); // Ethereum and Polygon
    let msg = Any2EVMMessage {
        message_id: [0u8; 32],
        source_chain_selector: 1u64, // Valid chain
        sender: [0u8; 32],
        data: vec![1, 2, 3],
        token_amounts: vec![TokenAmount { token: [0u8; 32], amount: 100 }],
    };
    assert!(bridge._ccip_receive(msg).is_ok());

    let bad_msg = Any2EVMMessage {
        message_id: [1u8; 32],
        source_chain_selector: 99u64, // Invalid chain
        sender: [0u8; 32],
        data: vec![],
        token_amounts: vec![],
    };
    assert!(bridge._ccip_receive(bad_msg).is_err());
}