use std::collections::HashMap;

#[derive(Clone, Debug)]
struct Settlement {
    nonce: u64,
    recipient: String,
    amount: u64,
    executed: bool,
    epoch: u64,
}

struct BridgeAgent {
    settlements: HashMap<u64, Settlement>,
    nonce_counter: u64,
    current_epoch: u64,
    epoch_awards: HashMap<u64, u64>,
}

impl BridgeAgent {
    fn new() -> Self {
        BridgeAgent {
            settlements: HashMap::new(),
            nonce_counter: 0,
            current_epoch: 1,
            epoch_awards: HashMap::new(),
        }
    }

    fn deposit_awards(&mut self, epoch: u64, amount: u64) {
        *self.epoch_awards.entry(epoch).or_insert(0) += amount;
    }

    fn create_settlement(&mut self, recipient: String, amount: u64) -> u64 {
        self.nonce_counter += 1;
        let nonce = self.nonce_counter;
        let settlement = Settlement {
            nonce,
            recipient,
            amount,
            executed: false,
            epoch: self.current_epoch,
        };
        self.settlements.insert(nonce, settlement);
        nonce
    }

    fn execute_settlement(&mut self, nonce: u64) -> Result<u64, &'static str> {
        let settlement = self.settlements.get_mut(&nonce)
            .ok_or("Settlement not found")?;
        
        if settlement.executed {
            return Err("Already executed");
        }
        
        settlement.executed = true;
        let award = self.epoch_awards.get(&settlement.epoch).copied().unwrap_or(0);
        
        Ok(settlement.amount + award)
    }

    fn retry_settlement(&mut self, old_nonce: u64, new_recipient: String) -> Result<u64, &'static str> {
        let old = self.settlements.get(&old_nonce)
            .ok_or("Old settlement not found")?;
        
        if !old.executed {
            return Err("Original not executed");
        }
        
        // VULNERABLE: Marks as executed but keeps settlement, reuses same nonce space
        // Allows replay to drain accumulated awards from same epoch
        let mut new_settlement = old.clone();
        new_settlement.recipient = new_recipient;
        new_settlement.executed = false;
        // BUG: old_nonce settlement remains in map with executed=true, but we can
        // create new settlement with same epoch that inherits accumulated awards
        
        self.nonce_counter += 1;
        let new_nonce = self.nonce_counter;
        new_settlement.nonce = new_nonce;
        self.settlements.insert(new_nonce, new_settlement);
        
        Ok(new_nonce)
    }
}

fn main() {
    let mut agent = BridgeAgent::new();
    agent.deposit_awards(1, 100);
    let nonce = agent.create_settlement("alice".to_string(), 50);
    let _ = agent.execute_settlement(nonce);
    agent.deposit_awards(1, 200); // More awards accumulated in same epoch
    
    // Attacker retries multiple times, each gets full accumulated awards
    let retry1 = agent.retry_settlement(nonce, "attacker".to_string()).unwrap();
    let payout1 = agent.execute_settlement(retry1).unwrap(); // Gets 50 + 300 = 350
    
    agent.deposit_awards(1, 500); // Even more awards
    let retry2 = agent.retry_settlement(nonce, "attacker2".to_string()).unwrap();
    let payout2 = agent.execute_settlement(retry2).unwrap(); // Gets 50 + 800 = 850
    
    // Attacker drained 1200 in awards from repeated replays
    assert!(payout1 > 50 || payout2 > 50); // Demonstrates inflated payouts
}