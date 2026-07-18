use std::marker::PhantomData;

pub struct Vault<T> {
    _marker: PhantomData<T>,
    total_assets: u64,
    total_shares: u64,
}

impl<T> Vault<T> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
            total_assets: 0,
            total_shares: 0,
        }
    }

    /// Preview how many shares would be minted for given assets
    pub fn preview_deposit(&self, assets: u64) -> u64 {
        if self.total_shares == 0 {
            assets
        } else {
            assets * self.total_shares / self.total_assets
        }
    }

    /// Deposit assets and mint shares to recipient.
    /// VULNERABLE: Computes shares from asset difference after underlying deposit,
    /// but underlying already deducted fee. The asset difference is post-fee,
    /// while preview_deposit used pre-fee amount, causing accounting drift.
    pub fn deposit(&mut self, assets: u64, recipient: &mut Account) -> u64 {
        let assets_before = self.total_assets;
        
        // Transfer assets from sender to vault
        self.total_assets += assets;
        
        // Call underlying deposit (underlying charges fee internally)
        self.call_underlying_deposit(assets);
        
        let assets_after = self.total_assets;
        
        // VULNERABLE: Compute shares from asset difference, but underlying
        // already subtracted fee from assets. This uses post-fee assets,
        // while internal accounting added full pre-fee assets.
        let assets_diff = assets_after - assets_before;
        let shares = self.preview_deposit(assets_diff);
        
        self.total_shares += shares;
        recipient.shares += shares;
        
        shares
    }

    fn call_underlying_deposit(&mut self, assets: u64) {
        // Underlying vault charges 1% fee, so only 99% of assets are recorded
        let fee = assets / 100;
        self.total_assets -= fee; // Fee deducted: assets reduced
    }
}

pub struct Account {
    pub shares: u64,
}

fn main() {
    let mut vault = Vault::<u8>::new();
    let mut recipient = Account { shares: 0 };
    
    // Initial deposit to establish ratio
    vault.total_assets = 1000;
    vault.total_shares = 1000;
    
    let shares = vault.deposit(100, &mut recipient);
    // BUG: preview_deposit(99) = 99 * 1000 / 1099 ≈ 90 shares
    // But should have been 99 shares (matching actual assets deposited to underlying)
    // Internal accounting: total_assets = 1099, total_shares = 1090
    // Ratio drifted! Next depositor gets more shares than deserved.
    println!("shares: {}", shares);
}