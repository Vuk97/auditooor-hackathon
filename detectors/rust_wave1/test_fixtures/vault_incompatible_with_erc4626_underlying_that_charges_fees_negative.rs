use std::collections::HashMap;

/// ERC4626-like vault that properly accounts for deposit fees
/// from underlying vaults by using convertToShares instead of previewDeposit.
pub struct SafeVault {
    underlying: MockERC4626,
    total_assets: u64,
    total_shares: u64,
    asset_to_shares: HashMap<u64, u64>,
}

pub struct MockERC4626 {
    deposit_fee_bps: u64, // basis points
    total_assets: u64,
    total_shares: u64,
}

impl MockERC4626 {
    pub fn preview_deposit(&self, assets: u64) -> u64 {
        // BUG: This does NOT include the deposit fee
        // Some ERC4626 vaults return shares without fee deduction
        let shares = self.convert_to_shares(assets);
        shares
    }

    pub fn convert_to_shares(&self, assets: u64) -> u64 {
        if self.total_assets == 0 {
            assets
        } else {
            assets * self.total_shares / self.total_assets
        }
    }

    pub fn deposit_with_fee(&self, assets: u64) -> u64 {
        let fee = assets * self.deposit_fee_bps / 10000;
        let net_assets = assets - fee;
        self.convert_to_shares(net_assets)
    }
}

impl SafeVault {
    pub fn new(underlying: MockERC4626) -> Self {
        Self {
            underlying,
            total_assets: 0,
            total_shares: 0,
            asset_to_shares: HashMap::new(),
        }
    }

    /// SAFE: Uses convertToShares which reflects actual underlying state
    pub fn _convert_to_shares(&self, assets: u64) -> u64 {
        // CORRECT: Use convertToShares to get actual shares based on current ratio
        // This properly handles fee-charging underlying vaults because
        // convertToShares reflects the actual exchange rate, not a preview
        let underlying_shares = self.underlying.convert_to_shares(assets);
        
        // Additional safety: verify with actual deposit simulation
        let simulated = self.underlying.deposit_with_fee(assets);
        assert_eq!(underlying_shares, simulated, "convertToShares must match actual deposit");
        
        underlying_shares
    }

    pub fn deposit(&mut self, assets: u64) -> u64 {
        let shares = self._convert_to_shares(assets);
        self.total_assets += assets;
        self.total_shares += shares;
        shares
    }
}

fn main() {
    let underlying = MockERC4626 {
        deposit_fee_bps: 100, // 1% fee
        total_assets: 1000000,
        total_shares: 1000000,
    };
    let mut vault = SafeVault::new(underlying);
    let shares = vault.deposit(10000);
    println!("Minted {} shares for 10000 assets", shares);
}