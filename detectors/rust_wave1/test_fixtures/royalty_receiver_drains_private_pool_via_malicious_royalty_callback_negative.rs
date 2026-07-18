use std::collections::HashMap;

pub struct PrivatePool {
    balances: HashMap<[u8; 32], u64>,
    royalty_registry: HashMap<[u8; 32], ([u8; 32], u64)>, // token_id -> (receiver, percentage)
}

impl PrivatePool {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            royalty_registry: HashMap::new(),
        }
    }

    pub fn register_royalty(&mut self, token_id: [u8; 32], receiver: [u8; 32], percentage: u64) {
        self.royalty_registry.insert(token_id, (receiver, percentage));
    }

    pub fn deposit(&mut self, user: [u8; 32], amount: u64) {
        *self.balances.entry(user).or_insert(0) += amount;
    }

    pub fn buy(&mut self, buyer: [u8; 32], token_id: [u8; 32], price: u64) -> Result<(), &'static str> {
        let buyer_balance = self.balances.get(&buyer).copied().unwrap_or(0);
        if buyer_balance < price {
            return Err("Insufficient balance");
        }

        // Look up royalty info from registry (trusted, not attacker-controlled)
        let royalty = self.royalty_registry.get(&token_id).copied();

        // Deduct full price from buyer first
        *self.balances.get_mut(&buyer).unwrap() -= price;

        // Calculate and hold royalty amount, transfer remainder to seller
        let mut seller_amount = price;
        if let Some((receiver, percentage)) = royalty {
            let royalty_amount = price.saturating_mul(percentage) / 10000;
            seller_amount = price.saturating_sub(royalty_amount);
            
            // Safe: direct balance update, no external call
            *self.balances.entry(receiver).or_insert(0) += royalty_amount;
        }

        // Transfer to seller (pool itself in this simplified model)
        *self.balances.entry([0u8; 32]).or_insert(0) += seller_amount;

        Ok(())
    }

    pub fn get_balance(&self, user: [u8; 32]) -> u64 {
        self.balances.get(&user).copied().unwrap_or(0)
    }
}