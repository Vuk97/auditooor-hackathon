use std::cmp::max;

/// ERC4626 vault with symmetric deposit/mint on first deposit
pub struct Vault {
    total_assets: u128,
    total_shares: u128,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            total_assets: 0,
            total_shares: 0,
        }
    }

    /// Convert assets to shares using the standard formula
    fn convert_to_shares(&self, assets: u128) -> u128 {
        if self.total_assets == 0 || self.total_shares == 0 {
            assets // 1:1 on first deposit
        } else {
            assets * self.total_shares / self.total_assets
        }
    }

    /// Preview mint: how many assets needed for given shares
    fn preview_mint(&self, shares: u128) -> u128 {
        if self.total_assets == 0 || self.total_shares == 0 {
            shares // 1:1 on first deposit, symmetric with convertToShares
        } else {
            // Round up: (shares * total_assets + total_shares - 1) / total_shares
            (shares * self.total_assets + self.total_shares - 1) / self.total_shares
        }
    }

    /// Deposit assets, receive shares
    pub fn deposit(&mut self, assets: u128) -> u128 {
        let shares = self.convert_to_shares(assets);
        self.total_assets += assets;
        self.total_shares += shares;
        shares
    }

    /// Mint shares, pay assets
    pub fn mint(&mut self, shares: u128) -> u128 {
        let assets = self.preview_mint(shares);
        self.total_assets += assets;
        self.total_shares += shares;
        assets
    }
}

fn main() {
    let mut vault = Vault::new();
    // First depositor: both deposit(1000) and mint(1000) give same 1:1 result
    let shares_from_deposit = vault.deposit(1000);
    assert_eq!(shares_from_deposit, 1000);
    
    let mut vault2 = Vault::new();
    let assets_for_mint = vault2.mint(1000);
    assert_eq!(assets_for_mint, 1000);
}