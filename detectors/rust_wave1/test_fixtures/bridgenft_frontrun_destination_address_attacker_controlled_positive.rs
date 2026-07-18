use std::collections::HashMap;

/// Vulnerable bridge: destination address supplied at execution time, after approval
pub struct NftBridge {
    approved_bridges: HashMap<u64, BridgeApproval>,
    balances: HashMap<u64, u64>,
}

#[derive(Clone, Debug)]
pub struct BridgeApproval {
    pub token_id: u64,
    pub owner: String,
    pub approved: bool,
    // NOTE: destination is NOT stored here — supplied later!
}

impl NftBridge {
    pub fn new() -> Self {
        Self {
            approved_bridges: HashMap::new(),
            balances: HashMap::new(),
        }
    }

    pub fn mint(&mut self, token_id: u64, _owner: String) {
        self.balances.insert(token_id, 1);
    }

    /// Approve bridge WITHOUT specifying destination
    pub fn approve_bridge(&mut self, token_id: u64, owner: String) -> Result<(), String> {
        if self.balances.get(&token_id).is_none() {
            return Err("Token does not exist".to_string());
        }
        
        let approval = BridgeApproval {
            token_id,
            owner,
            approved: true,
        };
        
        self.approved_bridges.insert(token_id, approval);
        Ok(())
    }

    /// VULNERABLE: destination supplied at execution time, after approval
    /// Attacker can frontrun this with their own destination address
    pub fn bridge_nft(&mut self, token_id: u64, destination: String) -> Result<String, String> {
        let approval = self.approved_bridges.get(&token_id)
            .ok_or("No approved bridge request")?;
        
        if !approval.approved {
            return Err("Bridge not approved".to_string());
        }
        
        // CRITICAL: No verification that destination matches owner's intent!
        // Attacker supplies any destination address here
        
        // Burn on source
        self.balances.remove(&token_id);
        self.approved_bridges.remove(&token_id);
        
        // Mint to attacker-controlled destination
        Ok(destination) // attacker-controlled!
    }
}

fn main() {
    let mut bridge = NftBridge::new();
    bridge.mint(1, "alice".to_string());
    
    // Alice approves (no destination specified yet)
    bridge.approve_bridge(1, "alice".to_string()).unwrap();
    
    // ATTACK: Bob frontruns with his own destination
    // In blockchain: Bob sees Alice's approve tx, submits bridge_nft with his address
    let stolen = bridge.bridge_nft(1, "bob_attacker_addr".to_string()).unwrap();
    assert_eq!(stolen, "bob_attacker_addr"); // Alice's NFT goes to Bob!
}