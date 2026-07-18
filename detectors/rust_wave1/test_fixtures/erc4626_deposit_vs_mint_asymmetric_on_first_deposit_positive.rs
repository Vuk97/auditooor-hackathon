use std::cmp::max;

/// ERC4626 vault with ASYMMETRIC deposit/mint on first deposit
/// BUG: deposit uses convertToShares (1:1) but mint uses previewMint with different logic
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

    /// Preview mint: BUG - uses asymmetric logic on first deposit
    /// This rounds up even on first deposit, unlike convertToShares
    fn preview_mint(&self, shares: u128) -> u128 {
        if self.total_assets == 0 || self.total_shares == 0 {
            // BUG: Should be shares (1:1) to match convertToShares,
            // but instead uses different formula causing asymmetry
            max(shares, 1) // Wrong: forces minimum 1, breaks 1:1 symmetry
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
    // First depositor via deposit: gets 1000 shares for 1000 assets (1:1)
    let shares_from_deposit = vault.deposit(1000);
    assert_eq!(shares_from_deposit, 1000);
    
    let mut vault2 = Vault::new();
    // First depositor via mint: BUG - pays different amount due to asymmetric previewMint
    let assets_for_mint = vault2.mint(1000);
    // Would expect 1000 assets for 1000 shares, but gets different due to bug
    println!("assets_for_mint = {}", assets_for_mint);
}