use std::collections::HashMap;

/// ERC4626-like vault with proper accounting.
/// total_assets tracks only assets backed by shares.
#[derive(Debug, Clone)]
pub struct Vault {
    total_assets: u128,
    total_shares: u128,
    balances: HashMap<u64, u128>, // user -> shares
}

impl Vault {
    pub fn new() -> Self {
        Self {
            total_assets: 0,
            total_shares: 0,
            balances: HashMap::new(),
        }
    }

    /// Mint shares proportional to assets deposited.
    pub fn deposit(&mut self, user: u64, assets: u128) -> u128 {
        let shares = if self.total_shares == 0 {
            assets
        } else {
            assets * self.total_shares / self.total_assets
        };
        self.total_assets += assets;
        self.total_shares += shares;
        *self.balances.entry(user).or_insert(0) += shares;
        shares
    }

    /// Proper rebase: only protocol-controlled mechanism that mints BOTH
    /// assets AND matching shares to keep ratio constant.
    pub fn protocol_rebase(&mut self, asset_increase: u128, share_increase: u128) {
        // Both increase proportionally, no dilution
        self.total_assets += asset_increase;
        self.total_shares += share_increase;
    }

    pub fn convert_to_assets(&self, shares: u128) -> u128 {
        if self.total_shares == 0 {
            shares
        } else {
            shares * self.total_assets / self.total_shares
        }
    }

    pub fn convert_to_shares(&self, assets: u128) -> u128 {
        if self.total_shares == 0 {
            assets
        } else {
            assets * self.total_shares / self.total_assets
        }
    }

    pub fn balance_of(&self, user: u64) -> u128 {
        *self.balances.get(&user).unwrap_or(&0)
    }
}

fn main() {
    let mut vault = Vault::new();
    vault.deposit(1, 1000);
    vault.deposit(2, 1000);
    
    // Protocol rebase with proportional share mint
    vault.protocol_rebase(100, 100);
    
    let user1_value = vault.convert_to_assets(vault.balance_of(1));
    let user2_value = vault.convert_to_assets(vault.balance_of(2));
    
    // Both users maintain proportional claim
    assert_eq!(user1_value, 1050);
    assert_eq!(user2_value, 1050);
    println!("Fair rebase: user1={}, user2={}", user1_value, user2_value);
}