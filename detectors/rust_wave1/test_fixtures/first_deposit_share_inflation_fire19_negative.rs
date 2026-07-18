const VIRTUAL_SHARES: u128 = 1_000_000;
const VIRTUAL_ASSETS: u128 = 1;
const MINIMUM_SHARES: u128 = 1_000;

pub struct SafeFire19Vault {
    total_assets: u128,
    total_shares: u128,
}

impl SafeFire19Vault {
    pub fn new() -> Self {
        Self {
            total_assets: 0,
            total_shares: 0,
        }
    }

    pub fn deposit(&mut self, assets: u128) -> u128 {
        let supply = self.total_shares + VIRTUAL_SHARES;
        let asset_balance = self.total_assets + VIRTUAL_ASSETS;
        let shares = assets
            .checked_mul(supply)
            .and_then(|n| n.checked_div(asset_balance))
            .expect("checked share math");
        assert!(shares >= MINIMUM_SHARES);
        self.total_assets += assets;
        self.total_shares += shares;
        shares
    }

    pub fn preview_deposit(&self, assets: u128) -> u128 {
        let supply = self.total_shares + VIRTUAL_SHARES;
        let asset_balance = self.total_assets + VIRTUAL_ASSETS;
        assets
            .checked_mul(supply)
            .and_then(|n| n.checked_div(asset_balance))
            .expect("checked preview")
    }

    pub fn convert_to_shares(&self, assets: u128) -> u128 {
        let supply = self.total_shares + VIRTUAL_SHARES;
        let asset_balance = self.total_assets + VIRTUAL_ASSETS;
        assets
            .checked_mul(supply)
            .and_then(|n| n.checked_div(asset_balance))
            .expect("checked conversion")
    }

    pub fn mint(&mut self, shares: u128) -> u128 {
        assert!(shares >= MINIMUM_SHARES);
        let assets = self.preview_mint(shares);
        self.total_assets += assets;
        self.total_shares += shares;
        assets
    }

    fn preview_mint(&self, shares: u128) -> u128 {
        let supply = self.total_shares + VIRTUAL_SHARES;
        let asset_balance = self.total_assets + VIRTUAL_ASSETS;
        shares
            .checked_mul(asset_balance)
            .and_then(|n| n.checked_add(supply - 1))
            .and_then(|n| n.checked_div(supply))
            .expect("checked mint preview")
    }
}
