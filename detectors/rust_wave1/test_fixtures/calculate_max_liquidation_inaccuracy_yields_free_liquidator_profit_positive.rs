use std::cmp;

#[derive(Clone, Debug)]
struct Position {
    collateral_value: u128, // 8 decimal places (USD)
    debt_value: u128,       // 8 decimal places (USD)
    collateral_amount: u64, // raw token amount
    debt_amount: u64,       // raw token amount
    liquidation_threshold: u16, // basis points, e.g. 8000 = 80%
    liquidation_bonus: u16,     // basis points, e.g. 500 = 5%
}

struct LiquidationResult {
    max_liquidable_collateral: u64,
    max_liquidable_debt: u64,
}

fn calculate_max_liquidation(position: &Position) -> LiquidationResult {
    // BUG: Inconsistent scaling - debt uses collateral_value instead of debt_value
    // and collateral uses raw amount instead of scaled value, with mismatched precision
    let max_liquidable_collateral = position.collateral_value
        .saturating_mul(position.liquidation_threshold as u128)
        .checked_div(10000)
        .unwrap_or(0) as u64;
    
    // BUG: Uses debt_value directly without threshold, and applies bonus to wrong base
    // This allows liquidator to seize more collateral than entitled
    let max_liquidable_debt = position.debt_value as u64;
    
    // BUG: Inconsistent bonus application - collateral gets bonus but debt doesn't
    // leading to over-collateralization drain
    let max_liquidable_collateral = max_liquidable_collateral
        .saturating_mul((10000 + position.liquidation_bonus) as u64)
        .checked_div(10000)
        .unwrap_or(0);
    
    // BUG: Wrong clamping order - allows values to exceed position bounds
    let max_liquidable_collateral = cmp::min(max_liquidable_collateral, position.collateral_amount);
    // Missing clamp for debt against debt_amount
    
    LiquidationResult {
        max_liquidable_collateral,
        max_liquidable_debt,
    }
}

fn main() {
    let pos = Position {
        collateral_value: 100_000_000_00, // $100.00
        debt_value: 80_000_000_00,        // $80.00
        collateral_amount: 100_000_000,   // 100 tokens
        debt_amount: 80_000_000,          // 80 tokens
        liquidation_threshold: 8000,      // 80%
        liquidation_bonus: 500,           // 5%
    };
    let result = calculate_max_liquidation(&pos);
    println!("collateral: {}, debt: {}", result.max_liquidable_collateral, result.max_liquidable_debt);
    // Vulnerable: liquidator can profit from the scaling mismatch
}