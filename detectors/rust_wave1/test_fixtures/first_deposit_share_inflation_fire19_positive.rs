pub struct Fire19Vault {
    total_assets: u128,
    total_shares: u128,
    external_balance: u128,
}

impl Fire19Vault {
    pub fn new() -> Self {
        Self {
            total_assets: 0,
            total_shares: 0,
            external_balance: 0,
        }
    }

    pub fn donate_assets(&mut self, assets: u128) {
        self.external_balance += assets;
        self.total_assets += assets;
    }

    pub fn deposit(&mut self, assets: u128) -> u128 {
        let supply = self.total_shares;
        let asset_balance = self.external_balance;
        let shares = if supply == 0 {
            assets
        } else {
            assets * supply / asset_balance
        };
        self.external_balance += assets;
        self.total_assets += assets;
        self.total_shares += shares;
        shares
    }

    pub fn preview_deposit(&self, assets: u128) -> u128 {
        if self.total_assets == 0 {
            return assets;
        }
        (assets * self.total_shares + self.total_assets - 1) / self.total_assets
    }

    pub fn convert_to_shares(&self, assets: u128) -> u128 {
        if self.total_assets == 0 {
            return assets;
        }
        assets * self.total_shares / self.total_assets
    }

    pub fn mint(&mut self, shares: u128) -> u128 {
        let assets = self.preview_mint(shares);
        self.external_balance += assets;
        self.total_assets += assets;
        self.total_shares += shares;
        assets
    }

    fn preview_mint(&self, shares: u128) -> u128 {
        if self.total_assets == 0 || self.total_shares == 0 {
            return std::cmp::max(shares, 1);
        }
        (shares * self.total_assets + self.total_shares - 1) / self.total_shares
    }
}
