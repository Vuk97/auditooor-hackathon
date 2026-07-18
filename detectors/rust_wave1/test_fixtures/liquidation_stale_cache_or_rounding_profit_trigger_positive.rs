use std::cmp;

struct Position {
    collateral_value: u128,
    debt_value: u128,
    collateral_amount: u64,
    debt_amount: u64,
    liquidation_bonus: u16,
}

struct LendingVault;

impl LendingVault {
    fn get_collateral_value(&self, token_id: u64) -> u128 {
        let cached_liquidity = self.get_position_liquidity_at_deposit(token_id);
        cached_liquidity * 2
    }

    fn get_position_liquidity_at_deposit(&self, _token_id: u64) -> u128 {
        1000
    }
}

fn calculate_max_liquidation(position: &Position) -> (u64, u64) {
    let max_liquidable_collateral = position.collateral_value
        .saturating_mul((10000 + position.liquidation_bonus) as u128)
        .checked_div(10000)
        .unwrap_or(0) as u64;

    let max_liquidable_debt = position.debt_value as u64;
    let max_liquidable_collateral = cmp::min(
        max_liquidable_collateral,
        position.collateral_amount,
    );

    (max_liquidable_collateral, max_liquidable_debt)
}

fn liquidate_bad_debt(debt: u128, collateral: u128) -> u128 {
    if collateral < debt {
        return collateral;
    }
    debt
}

fn liquidate_rounding_gap(seized_assets: u128, total_assets: u128, total_shares: u128) -> (u128, u128) {
    let repaid_assets = to_assets_up(seized_assets, total_assets, total_shares);
    let repaid_shares = to_shares_down(repaid_assets, total_assets, total_shares);
    (repaid_assets, repaid_shares)
}

fn to_assets_up(shares: u128, assets: u128, total_shares: u128) -> u128 {
    (shares * assets + total_shares - 1) / total_shares
}

fn to_shares_down(assets: u128, total_assets: u128, total_shares: u128) -> u128 {
    assets * total_shares / total_assets
}
