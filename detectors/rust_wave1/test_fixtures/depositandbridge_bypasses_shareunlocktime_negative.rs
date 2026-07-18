use std::time::{SystemTime, Duration};
use alloy_primitives::{Address, U256};

pub struct ShareToken {
    pub total_supply: U256,
    pub balances: std::collections::HashMap<Address, U256>,
    pub unlock_times: std::collections::HashMap<Address, u64>,
}

pub struct BridgeClient {
    pub endpoint: String,
}

impl BridgeClient {
    pub fn send(&self, to: Address, amount: U256) -> Result<(), String> {
        Ok(())
    }
}

impl ShareToken {
    pub fn new() -> Self {
        Self {
            total_supply: U256::ZERO,
            balances: std::collections::HashMap::new(),
            unlock_times: std::collections::HashMap::new(),
        }
    }

    pub fn mint(&mut self, to: Address, amount: U256) {
        let current = self.balances.get(&to).copied().unwrap_or(U256::ZERO);
        self.balances.insert(to, current + amount);
        self.total_supply += amount;
        // Set unlock time to 7 days from now
        let unlock_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 7 * 24 * 60 * 60;
        self.unlock_times.insert(to, unlock_at);
    }

    pub fn check_unlocked(&self, account: Address) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        match self.unlock_times.get(&account) {
            Some(unlock_time) => now >= *unlock_time,
            None => true,
        }
    }

    pub fn burn(&mut self, from: Address, amount: U256) -> Result<(), String> {
        if !self.check_unlocked(from) {
            return Err("Shares are locked".to_string());
        }
        let current = self.balances.get(&from).copied().unwrap_or(U256::ZERO);
        if current < amount {
            return Err("Insufficient balance".to_string());
        }
        self.balances.insert(from, current - amount);
        self.total_supply -= amount;
        Ok(())
    }

    pub fn deposit_and_bridge(
        &mut self,
        bridge: &BridgeClient,
        user: Address,
        amount: U256,
        dest_chain: Address,
    ) -> Result<(), String> {
        self.mint(user, amount);
        
        // FIX: Enforce share unlock time before bridging
        if !self.check_unlocked(user) {
            return Err("Shares must unlock before bridging".to_string());
        }
        
        // Burn shares and bridge underlying assets
        self.burn(user, amount)?;
        bridge.send(dest_chain, amount)?;
        Ok(())
    }
}

fn main() {
    let mut token = ShareToken::new();
    let bridge = BridgeClient { endpoint: "http://bridge.example".to_string() };
    let user = Address::ZERO;
    let dest = Address::ZERO;
    let _ = token.deposit_and_bridge(&bridge, user, U256::from(100), dest);
}