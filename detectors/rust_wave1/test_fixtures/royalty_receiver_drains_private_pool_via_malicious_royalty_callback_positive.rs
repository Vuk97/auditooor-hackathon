use std::collections::HashMap;

pub trait RoyaltyCallback {
    fn receive_royalty(&mut self, amount: u64);
}

pub struct ExternalRegistry;

impl ExternalRegistry {
    // Returns (receiver_address, royalty_amount) - attacker controls this for malicious NFTs
    pub fn royalty_info(_token_id: [u8; 32], _sale_price: u64) -> ([u8; 32], u64) {
        // In real scenario, this calls attacker-controlled contract
        ([0xAA; 32], 500) // 5% royalty
    }
}

pub struct PrivatePool {
    balances: HashMap<[u8; 32], u64>,
    callbacks: HashMap<[u8; 32], Box<dyn RoyaltyCallback>>, // VULNERABLE: stores external callbacks
}

impl PrivatePool {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            callbacks: HashMap::new(),
        }
    }

    pub fn register_callback(&mut self, token_id: [u8; 32], callback: Box<dyn RoyaltyCallback>) {
        self.callbacks.insert(token_id, callback);
    }

    pub fn deposit(&mut self, user: [u8; 32], amount: u64) {
        *self.balances.entry(user).or_insert(0) += amount;
    }

    pub fn buy(&mut self, buyer: [u8; 32], token_id: [u8; 32], price: u64) -> Result<(), &'static str> {
        let buyer_balance = self.balances.get(&buyer).copied().unwrap_or(0);
        if buyer_balance < price {
            return Err("Insufficient balance");
        }

        // VULNERABLE: Fetch royalty receiver from external/attacker-controlled source
        let (royalty_receiver, royalty_bps) = ExternalRegistry::royalty_info(token_id, price);
        let royalty_amount = price.saturating_mul(royalty_bps) / 10000;
        let seller_amount = price.saturating_sub(royalty_amount);

        // Deduct from buyer
        *self.balances.get_mut(&buyer).unwrap() -= price;

        // VULNERABLE: External call to royalty receiver BEFORE state updates complete
        // This allows reentrancy - attacker callback can reenter buy() with same/different token
        if let Some(callback) = self.callbacks.get_mut(&royalty_receiver) {
            callback.receive_royalty(royalty_amount); // Reentrancy point!
        }

        // State updates happen AFTER external call - classic reentrancy vulnerability
        *self.balances.entry(royalty_receiver).or_insert(0) += royalty_amount;
        *self.balances.entry([0u8; 32]).or_insert(0) += seller_amount;

        Ok(())
    }

    pub fn get_balance(&self, user: [u8; 32]) -> u64 {
        self.balances.get(&user).copied().unwrap_or(0)
    }
}

// Attacker's malicious callback that reenters
pub struct AttackerCallback {
    pub pool: *mut PrivatePool,
    pub buyer: [u8; 32],
    pub token_id: [u8; 32],
    pub price: u64,
    pub reentered: bool,
}

impl RoyaltyCallback for AttackerCallback {
    fn receive_royalty(&mut self, _amount: u64) {
        if !self.reentered {
            self.reentered = true;
            unsafe {
                // Reenter the pool to drain additional funds
                let _ = (*self.pool).buy(self.buyer, self.token_id, self.price);
            }
        }
    }
}