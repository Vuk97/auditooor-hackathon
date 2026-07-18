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

/// Bridge MISSING source chain validation - VULNERABLE
pub struct BridgeCCIP {
    // allowed_source_chains exists but is NEVER CHECKED in _ccip_receive
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

    /// VULNERABLE: No validation of message.source_chain_selector
    pub fn _ccip_receive(&mut self, message: Any2EVMMessage) -> Result<(), &'static str> {
        // MISSING: if !self.allowed_source_chains.contains(&message.source_chain_selector)
        // Attacker can send from any chain, including low-fee chains to exploit

        // Process token amounts without source validation
        for token_amount in &message.token_amounts {
            self.total_minted = self.total_minted.saturating_add(token_amount.amount);
        }

        // Process message data
        let _ = message.data;

        Ok(())
    }

    // Allowlist setter that is never used in receive
    pub fn add_allowed_chain(&mut self, chain_selector: u64) {
        self.allowed_source_chains.insert(chain_selector);
    }
}

fn main() {
    let mut bridge = BridgeCCIP::new(vec![1u64, 2u64]); // Ethereum and Polygon
    let msg = Any2EVMMessage {
        message_id: [0u8; 32],
        source_chain_selector: 99u64, // ATTACKER: unauthorized low-fee chain
        sender: [0u8; 32],
        data: vec![1, 2, 3],
        token_amounts: vec![TokenAmount { token: [0u8; 32], amount: 1000000 }],
    };
    // VULNERABLE: This succeeds when it should fail!
    assert!(bridge._ccip_receive(msg).is_ok());
    assert_eq!(bridge.total_minted, 1000000);
}