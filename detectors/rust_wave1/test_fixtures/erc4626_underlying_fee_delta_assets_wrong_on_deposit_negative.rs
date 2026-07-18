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
    /// CORRECT: Use the returned shares from underlying deposit, not asset difference.
    pub fn deposit(&mut self, assets: u64, recipient: &mut Account) -> u64 {
        let shares = self.preview_deposit(assets);
        
        // Transfer assets from sender to vault
        self.total_assets += assets;
        self.total_shares += shares;
        
        // In real ERC4626, call underlying.deposit and use returned shares
        let actual_shares = self.call_underlying_deposit(assets);
        
        // CORRECT: Use actual shares returned by underlying, which accounts for fees
        recipient.shares += actual_shares;
        
        actual_shares
    }

    fn call_underlying_deposit(&self, assets: u64) -> u64 {
        // Underlying vault may charge fee, e.g., 1% fee means 0.99*assets worth of shares
        let fee = assets / 100; // 1% fee
        assets - fee // shares minted (simplified)
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
    assert_eq!(shares, 99); // 1% fee applied
    assert_eq!(recipient.shares, 99);
}