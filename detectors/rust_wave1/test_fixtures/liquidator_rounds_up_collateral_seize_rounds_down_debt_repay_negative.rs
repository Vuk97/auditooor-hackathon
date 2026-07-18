use std::cmp;

pub struct Position {
    pub collateral: u64,
    pub debt: u64,
}

pub struct LiquidationResult {
    pub collateral_seized: u64,
    pub debt_repaid: u64,
}

/// Clean: consistently round down both values
pub fn liquidate_position(
    position: &Position,
    collateral_price: u64,
    debt_price: u64,
    liquidation_bonus: u64, // basis points, e.g. 500 = 5%
) -> Option<LiquidationResult> {
    let total_collateral_value = position.collateral.checked_mul(collateral_price)?;
    let total_debt_value = position.debt.checked_mul(debt_price)?;
    
    // Both rounded down consistently
    let collateral_to_seize = total_debt_value
        .checked_mul(10_000 + liquidation_bonus)?
        .checked_div(collateral_price)?
        .checked_div(10_000)?;
    
    let debt_to_repay = total_debt_value
        .checked_div(debt_price)?;
    
    let collateral_to_seize = cmp::min(collateral_to_seize, position.collateral);
    let debt_to_repay = cmp::min(debt_to_repay, position.debt);
    
    Some(LiquidationResult {
        collateral_seized: collateral_to_seize,
        debt_repaid: debt_to_repay,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_liquidate() {
        let pos = Position { collateral: 1000, debt: 500 };
        let result = liquidate_position(&pos, 2, 1, 500).unwrap();
        assert_eq!(result.collateral_seized, 525);
        assert_eq!(result.debt_repaid, 500);
    }
}