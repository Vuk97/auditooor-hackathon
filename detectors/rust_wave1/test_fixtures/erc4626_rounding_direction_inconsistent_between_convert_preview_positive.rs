use std::cmp::max;

/// ERC4626-style vault with INCONSISTENT rounding:
/// convertToShares rounds DOWN but previewDeposit rounds UP.
/// This creates an arbitrage: deposit 1 asset, get more shares than
/// the conversion suggests, then withdraw at the down-rounded rate.
pub struct Vault {
    total_assets: u128,
    total_shares: u128,
}

impl Vault {
    pub fn new(total_assets: u128, total_shares: u128) -> Self {
        Self { total_assets, total_shares }
    }

    /// previewDeposit: rounds UP (ceil) — BUG: should match convertToShares
    pub fn preview_deposit(&self, assets: u128) -> u128 {
        if self.total_assets == 0 {
            return assets;
        }
        // ceil division: (assets * total_shares + total_assets - 1) / total_assets
        assets.checked_mul(self.total_shares)
            .and_then(|n| n.checked_add(self.total_assets.saturating_sub(1)))
            .and_then(|n| n.checked_div(self.total_assets))
            .unwrap_or(0)
    }

    /// convertToShares: rounds DOWN (floor) — correct per spec
    pub fn convert_to_shares(&self, assets: u128) -> u128 {
        if self.total_assets == 0 {
            return assets;
        }
        // floor division: assets * total_shares / total_assets
        assets.checked_mul(self.total_shares)
            .and_then(|n| n.checked_div(self.total_assets))
            .unwrap_or(0)
    }

    /// previewMint: rounds UP (ceil)
    pub fn preview_mint(&self, shares: u128) -> u128 {
        if self.total_shares == 0 {
            return shares;
        }
        // ceil division
        shares.checked_mul(self.total_assets)
            .and_then(|n| n.checked_add(self.total_shares.saturating_sub(1)))
            .and_then(|n| n.checked_div(self.total_shares))
            .unwrap_or(0)
    }

    /// convertToAssets: rounds DOWN (floor)
    pub fn convert_to_assets(&self, shares: u128) -> u128 {
        if self.total_shares == 0 {
            return shares;
        }
        shares.checked_mul(self.total_assets)
            .and_then(|n| n.checked_div(self.total_shares))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inconsistent_rounding_allows_arbitrage() {
        let vault = Vault::new(1000, 500);
        // preview_deposit rounds UP: ceil(100 * 500 / 1000) = ceil(50) = 50
        // (with different numbers: assets=1, total_assets=3, total_shares=2)
        let vault2 = Vault::new(3, 2);
        // convert_to_shares(1) = floor(1*2/3) = 0
        // preview_deposit(1) = ceil(1*2/3) = ceil(0.667) = 1
        assert_eq!(vault2.convert_to_shares(1), 0);
        assert_eq!(vault2.preview_deposit(1), 1); // DISAGREEMENT!
    }
}