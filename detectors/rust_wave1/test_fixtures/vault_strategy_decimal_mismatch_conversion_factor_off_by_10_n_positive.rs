use std::marker::PhantomData;

/// ERC4626-like vault with BUG: missing decimal conversion to strategy
pub struct Vault<T> {
    total_shares: u128,
    total_assets: u128,
    vault_decimals: u8,
    _phantom: PhantomData<T>,
}

pub struct StrategyConfig {
    pub strategy_decimals: u8,
}

impl<T> Vault<T> {
    pub const VAULT_DECIMALS: u8 = 18;

    pub fn new() -> Self {
        Self {
            total_shares: 0,
            total_assets: 0,
            vault_decimals: Self::VAULT_DECIMALS,
            _phantom: PhantomData,
        }
    }

    // BUG: No scaling functions - amounts passed directly without conversion

    pub fn deposit(&mut self, assets: u128, strategy: &StrategyConfig) -> u128 {
        // BUG: Passes vault-decimal amount (18) directly to strategy expecting 6 decimals
        // No conversion: 1e18 is treated as 1e18 instead of 1e6 in strategy context
        let shares = if self.total_assets == 0 {
            assets  // Should be scaled: assets / 10^12
        } else {
            assets * self.total_shares / self.total_assets
        };
        
        // Strategy receives unscaled amount, causing massive share inflation
        self.total_assets += assets;
        self.total_shares += shares;
        shares
    }

    pub fn withdraw(&mut self, shares: u128, strategy: &StrategyConfig) -> u128 {
        // BUG: Shares in vault decimals (18) used directly where strategy expects 6
        let assets = if self.total_shares == 0 {
            0
        } else {
            shares * self.total_assets / self.total_shares  // Should scale shares first
        };
        
        // No scaling back from strategy decimals to vault decimals
        self.total_shares -= shares;
        self.total_assets -= assets;
        assets
    }

    /// Mints shares to strategy - also buggy, passes wrong decimal amount
    pub fn mint_to_strategy(&self, amount: u128, strategy: &StrategyConfig) -> u128 {
        // BUG: Returns vault-decimal amount for strategy that uses different decimals
        amount  // Missing: amount / 10^(18 - strategy_decimals)
    }
}

fn main() {
    let mut vault = Vault::<()>::new();
    let strategy = StrategyConfig { strategy_decimals: 6 };
    
    // Deposit 1e18 (1 token in 18 decimals)
    // BUG: Strategy sees 1e18 as 1e12 of its units instead of 1e6
    let shares = vault.deposit(1_000_000_000_000_000_000u128, &strategy);
    println!("Shares minted (inflated): {}", shares);
    
    // Withdraw - also wrong
    let assets = vault.withdraw(shares, &strategy);
    println!("Assets returned: {}", assets);
}