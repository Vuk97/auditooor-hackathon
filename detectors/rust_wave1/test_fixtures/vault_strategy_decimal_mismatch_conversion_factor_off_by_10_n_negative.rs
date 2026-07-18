use std::marker::PhantomData;

/// ERC4626-like vault with proper decimal conversion to strategy
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

    /// Properly scales amount from vault decimals to strategy decimals
    fn scale_to_strategy(amount: u128, strategy_decimals: u8) -> u128 {
        let vault_decimals = Self::VAULT_DECIMALS as u32;
        let strat_decimals = strategy_decimals as u32;
        
        if strat_decimals >= vault_decimals {
            amount * 10u128.pow(strat_decimals - vault_decimals)
        } else {
            amount / 10u128.pow(vault_decimals - strat_decimals)
        }
    }

    /// Properly scales amount from strategy decimals to vault decimals
    fn scale_to_vault(amount: u128, strategy_decimals: u8) -> u128 {
        let vault_decimals = Self::VAULT_DECIMALS as u32;
        let strat_decimals = strategy_decimals as u32;
        
        if strat_decimals >= vault_decimals {
            amount / 10u128.pow(strat_decimals - vault_decimals)
        } else {
            amount * 10u128.pow(vault_decimals - strat_decimals)
        }
    }

    pub fn deposit(&mut self, assets: u128, strategy: &StrategyConfig) -> u128 {
        // Scale from vault decimals (18) to strategy decimals before calling strategy
        let scaled_assets = Self::scale_to_strategy(assets, strategy.strategy_decimals);
        
        // Simulate strategy receiving scaled amount
        let shares = if self.total_assets == 0 {
            scaled_assets
        } else {
            scaled_assets * self.total_shares / self.total_assets
        };
        
        // Scale back to vault decimals for internal accounting
        let vault_shares = Self::scale_to_vault(shares, strategy.strategy_decimals);
        
        self.total_assets += assets;
        self.total_shares += vault_shares;
        vault_shares
    }

    pub fn withdraw(&mut self, shares: u128, strategy: &StrategyConfig) -> u128 {
        // Scale shares to strategy decimals for strategy calculation
        let scaled_shares = Self::scale_to_strategy(shares, strategy.strategy_decimals);
        
        let assets = if self.total_shares == 0 {
            0
        } else {
            scaled_shares * self.total_assets / self.total_shares
        };
        
        // Scale back to vault decimals
        let vault_assets = Self::scale_to_vault(assets, strategy.strategy_decimals);
        
        self.total_shares -= shares;
        self.total_assets -= vault_assets;
        vault_assets
    }
}

fn main() {
    let mut vault = Vault::<()>::new();
    let strategy = StrategyConfig { strategy_decimals: 6 };
    
    // Deposit 1e18 (1 token in 18 decimals)
    let shares = vault.deposit(1_000_000_000_000_000_000u128, &strategy);
    println!("Shares minted: {}", shares);
    
    // Withdraw
    let assets = vault.withdraw(shares, &strategy);
    println!("Assets returned: {}", assets);
}