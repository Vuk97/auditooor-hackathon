use std::cmp;

pub struct Position {
    pub collateral: u64,
    pub debt: u64,
}

pub struct LiquidationResult {
    pub collateral_seized: u64,
    pub debt_repaid: u64,
}

/// Vulnerable: rounds UP collateral seized, rounds DOWN debt repaid
pub fn liquidate_position(
    position: &Position,
    collateral_price: u64,
    debt_price: u64,
    liquidation_bonus: u64, // basis points, e.g. 500 = 5%
) -> Option<LiquidationResult> {
    let total_collateral_value = position.collateral.checked_mul(collateral_price)?;
    let total_debt_value = position.debt.checked_mul(debt_price)?;
    
    // BUG: collateral rounded UP (ceiling division)
    let collateral_numerator = total_debt_value
        .checked_mul(10_000 + liquidation_bonus)?;
    let collateral_to_seize = (collateral_numerator + collateral_price * 10_000 - 1)
        .checked_div(collateral_price)?
        .checked_div(10_000)?;
    
    // BUG: debt rounded DOWN (floor division)
    let debt_to_repay = total_debt_value
        .checked_div(debt_price)?;
    
    let collateral_to_seize = cmp::min(collateral_to_seize, position.collateral);
    let debt_to_repay = cmp::min(debt_to_repay, position.debt);
    
    Some(LiquidationResult {
        collateral_seized: collateral_to_seize,
        debt_repaid: debt_to_repay,
    })
}

/// Helper showing the ceiling pattern explicitly
fn ceiling_div(a: u64, b: u64) -> Option<u64> {
    Some((a + b - 1).checked_div(b)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_liquidate_drains() {
        let pos = Position { collateral: 1000, debt: 500 };
        let result = liquidate_position(&pos, 2, 1, 500).unwrap();
        // With rounding up, collateral seized > fair value
        assert!(result.collateral_seized >= 525);
        // Multiple liquidations would drain extra collateral
    }
}