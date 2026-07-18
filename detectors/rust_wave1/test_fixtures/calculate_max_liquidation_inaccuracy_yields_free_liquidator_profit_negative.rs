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
    // Consistent scaling: both values use same 8-decimal precision
    let max_liquidable_debt = position.debt_value
        .saturating_mul(position.liquidation_threshold as u128)
        .checked_div(10000)
        .unwrap_or(0) as u64;
    
    // Apply same liquidation bonus to collateral, maintaining consistent scaling
    let max_liquidable_collateral = position.collateral_value
        .saturating_mul(position.liquidation_threshold as u128)
        .saturating_mul((10000 + position.liquidation_bonus) as u128)
        .checked_div(10000)
        .checked_div(10000)
        .unwrap_or(0) as u64;
    
    // Clamp to actual position amounts
    let max_liquidable_debt = cmp::min(max_liquidable_debt, position.debt_amount);
    let max_liquidable_collateral = cmp::min(max_liquidable_collateral, position.collateral_amount);
    
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
}