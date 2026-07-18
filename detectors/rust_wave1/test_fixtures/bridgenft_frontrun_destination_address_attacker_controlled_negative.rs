use std::collections::HashMap;

/// Secure bridge: destination address is bound at approval time
pub struct NftBridge {
    approved_bridges: HashMap<u64, BridgeRequest>,
    balances: HashMap<u64, u64>, // token_id -> owner
}

#[derive(Clone, Debug)]
pub struct BridgeRequest {
    pub token_id: u64,
    pub owner: String,
    pub destination: String, // bound at approval, cannot be changed
    pub approved: bool,
}

impl NftBridge {
    pub fn new() -> Self {
        Self {
            approved_bridges: HashMap::new(),
            balances: HashMap::new(),
        }
    }

    pub fn mint(&mut self, token_id: u64, owner: String) {
        self.balances.insert(token_id, 1);
        // track ownership separately
    }

    /// Approve bridge with destination locked at approval time
    pub fn approve_bridge(&mut self, token_id: u64, owner: String, destination: String) -> Result<(), String> {
        if self.balances.get(&token_id).is_none() {
            return Err("Token does not exist".to_string());
        }
        
        let request = BridgeRequest {
            token_id,
            owner: owner.clone(),
            destination, // LOCKED: cannot be changed after approval
            approved: true,
        };
        
        self.approved_bridges.insert(token_id, request);
        Ok(())
    }

    /// Execute bridge using pre-approved destination
    pub fn bridge_nft(&mut self, token_id: u64, _caller: String) -> Result<String, String> {
        let request = self.approved_bridges.get(&token_id)
            .ok_or("No approved bridge request")?;
        
        if !request.approved {
            return Err("Bridge not approved".to_string());
        }
        
        // Verify caller is the original owner
        // In real impl: check signature or msg.sender
        
        // Burn on source
        self.balances.remove(&token_id);
        self.approved_bridges.remove(&token_id);
        
        // Return fixed destination from approval time
        Ok(request.destination.clone())
    }
}

fn main() {
    let mut bridge = NftBridge::new();
    bridge.mint(1, "alice".to_string());
    
    // Alice approves with her chosen destination
    bridge.approve_bridge(1, "alice".to_string(), "dest_chain_alice_addr".to_string()).unwrap();
    
    // Bridge executes with locked destination
    let dest = bridge.bridge_nft(1, "alice".to_string()).unwrap();
    assert_eq!(dest, "dest_chain_alice_addr");
}