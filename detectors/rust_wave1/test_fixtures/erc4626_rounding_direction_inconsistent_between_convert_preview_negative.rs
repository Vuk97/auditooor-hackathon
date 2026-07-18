use std::cmp::max;

/// ERC4626-style vault with consistent rounding: previewDeposit and
/// convertToShares both round DOWN (floor), matching the spec.
pub struct Vault {
    total_assets: u128,
    total_shares: u128,
}

impl Vault {
    pub fn new(total_assets: u128, total_shares: u128) -> Self {
        Self { total_assets, total_shares }
    }

    /// previewDeposit: how many shares for given assets?  Rounds DOWN.
    pub fn preview_deposit(&self, assets: u128) -> u128 {
        if self.total_assets == 0 {
            return assets;
        }
        // floor division: assets * total_shares / total_assets
        assets.checked_mul(self.total_shares)
            .and_then(|n| n.checked_div(self.total_assets))
            .unwrap_or(0)
    }

    /// convertToShares: how many shares for given assets?  Rounds DOWN.
    pub fn convert_to_shares(&self, assets: u128) -> u128 {
        if self.total_assets == 0 {
            return assets;
        }
        // floor division: assets * total_shares / total_assets
        assets.checked_mul(self.total_shares)
            .and_then(|n| n.checked_div(self.total_assets))
            .unwrap_or(0)
    }

    /// previewMint: how many assets for given shares?  Rounds UP.
    pub fn preview_mint(&self, shares: u128) -> u128 {
        if self.total_shares == 0 {
            return shares;
        }
        // ceil division: (shares * total_assets + total_shares - 1) / total_shares
        shares.checked_mul(self.total_assets)
            .and_then(|n| n.checked_add(self.total_shares.saturating_sub(1)))
            .and_then(|n| n.checked_div(self.total_shares))
            .unwrap_or(0)
    }

    /// convertToAssets: how many assets for given shares?  Rounds DOWN.
    pub fn convert_to_assets(&self, shares: u128) -> u128 {
        if self.total_shares == 0 {
            return shares;
        }
        // floor division
        shares.checked_mul(self.total_assets)
            .and_then(|n| n.checked_div(self.total_shares))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistent_rounding_agrees() {
        let vault = Vault::new(1000, 500);
        // Both preview_deposit and convert_to_shares round down
        assert_eq!(vault.preview_deposit(100), 50);
        assert_eq!(vault.convert_to_shares(100), 50);
    }
}