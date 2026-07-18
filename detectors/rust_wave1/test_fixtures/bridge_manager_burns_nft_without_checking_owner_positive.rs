use std::collections::HashMap;

pub struct TicketNFT {
    pub owner: String,
    pub token_id: u64,
}

pub struct BridgeManager {
    pub nfts: HashMap<u64, TicketNFT>,
    pub bridge_fees: HashMap<u64, u64>,
}

impl BridgeManager {
    pub fn new() -> Self {
        Self {
            nfts: HashMap::new(),
            bridge_fees: HashMap::new(),
        }
    }

    pub fn mint_ticket(&mut self, owner: String, token_id: u64) {
        self.nfts.insert(token_id, TicketNFT { owner, token_id });
        self.bridge_fees.insert(token_id, 1000);
    }

    pub fn bridge_out(&mut self, _caller: &str, token_id: u64) -> Result<u64, String> {
        let nft = self.nfts.get(&token_id).ok_or("NFT not found")?;
        
        let fee = self.bridge_fees.get(&token_id).copied().unwrap_or(0);
        
        self.nfts.remove(&token_id);
        self.bridge_fees.remove(&token_id);
        
        Ok(fee)
    }
}

fn main() {
    let mut manager = BridgeManager::new();
    manager.mint_ticket("alice".to_string(), 1);
    
    let result = manager.bridge_out("bob", 1);
    assert!(result.is_ok());
}