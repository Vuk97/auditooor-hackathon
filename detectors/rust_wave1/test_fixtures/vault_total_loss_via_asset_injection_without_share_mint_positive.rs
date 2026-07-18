use std::collections::HashMap;

/// ERC4626-like vault with INSECURE accounting.
/// total_assets can be inflated WITHOUT minting shares.
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

    /// VULNERABLE: rebase inflates total_assets without minting shares.
    /// This directly credits "assets" to vault without share backing.
    pub fn rebase_mint_debt_to_vault(&mut self, asset_increase: u128) {
        // BUG: total_assets increases but total_shares unchanged!
        // Prior holders' convertToAssets() jumps.
        // New depositors get fewer shares per asset (inflated denominator).
        self.total_assets += asset_increase;
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
    vault.deposit(1, 1000); // user1 gets 1000 shares
    vault.deposit(2, 1000); // user2 gets 1000 shares
    
    // VULNERABLE: rebase mints debt directly to vault, no shares minted
    vault.rebase_mint_debt_to_vault(1000);
    
    let user1_value = vault.convert_to_assets(vault.balance_of(1));
    let user2_value = vault.convert_to_assets(vault.balance_of(2));
    
    // User1 and user2 claims inflated, but new depositor exploited
    println!("After malicious rebase: user1={}, user2={}", user1_value, user2_value);
    
    // Attacker deposits after rebase at inflated rate
    let attacker_shares = vault.deposit(99, 1000);
    println!("Attacker got {} shares for 1000 assets", attacker_shares);
    // Attacker's shares worth less than deposited due to prior inflation
}