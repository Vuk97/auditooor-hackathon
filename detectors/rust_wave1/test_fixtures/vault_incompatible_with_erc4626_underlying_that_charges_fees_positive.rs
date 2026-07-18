use std::collections::HashMap;

/// ERC4626-like vault that is INCOMPATIBLE with fee-charging underlying vaults.
/// Uses previewDeposit which may not reflect actual fees charged.
pub struct UnsafeVault {
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

impl UnsafeVault {
    pub fn new(underlying: MockERC4626) -> Self {
        Self {
            underlying,
            total_assets: 0,
            total_shares: 0,
            asset_to_shares: HashMap::new(),
        }
    }

    /// VULNERABLE: Uses previewDeposit which overstates shares for fee-charging vaults
    pub fn _convert_to_shares(&self, assets: u64) -> u64 {
        // BUG: previewDeposit may not account for deposit fees in underlying vault.
        // If underlying charges fees, previewDeposit returns shares for gross assets,
        // but actual deposit returns fewer shares. This overstates user's position.
        let shares = self.underlying.preview_deposit(assets);
        shares
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
    let mut vault = UnsafeVault::new(underlying);
    let shares = vault.deposit(10000);
    println!("Minted {} shares for 10000 assets (overstated!)", shares);
}