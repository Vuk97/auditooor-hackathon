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
        let current_liquidity = self.get_current_liquidity(token_id);
        current_liquidity * 2
    }

    fn get_current_liquidity(&self, token_id: u64) -> u128 {
        self.fetch_from_amm(token_id)
    }

    fn fetch_from_amm(&self, _token_id: u64) -> u128 {
        1000
    }
}

fn calculate_max_liquidation(position: &Position) -> (u64, u64) {
    let max_liquidable_debt = position.debt_value
        .checked_div(2)
        .unwrap_or(0) as u64;
    let max_liquidable_collateral = position.collateral_value
        .saturating_mul((10000 + position.liquidation_bonus) as u128)
        .checked_div(10000)
        .unwrap_or(0) as u64;

    let max_liquidable_debt = cmp::min(max_liquidable_debt, position.debt_amount);
    let max_liquidable_collateral = cmp::min(
        max_liquidable_collateral,
        position.collateral_amount,
    );

    (max_liquidable_collateral, max_liquidable_debt)
}

fn liquidate_bad_debt(env: &Env, borrower: &Address, debt: u128, collateral: u128) -> u128 {
    if collateral < debt {
        let deficit = debt - collateral;
        record_bad_debt(env, borrower, deficit);
        return collateral;
    }
    debt
}

fn liquidate_rounding_gap(seized_assets: u128, total_assets: u128, total_shares: u128) -> (u128, u128) {
    let repaid_assets = to_assets_up(seized_assets, total_assets, total_shares);
    let repaid_shares = to_shares_up(repaid_assets, total_assets, total_shares);
    let repaid_assets = to_assets_up(repaid_shares, total_assets, total_shares);
    (repaid_assets, repaid_shares)
}

struct Env;
struct Address;

fn record_bad_debt(_: &Env, _: &Address, _: u128) {}

fn to_assets_up(shares: u128, assets: u128, total_shares: u128) -> u128 {
    (shares * assets + total_shares - 1) / total_shares
}

fn to_shares_up(assets: u128, total_assets: u128, total_shares: u128) -> u128 {
    (assets * total_shares + total_assets - 1) / total_assets
}
