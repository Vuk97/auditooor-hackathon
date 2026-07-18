use std::cmp;

pub struct Position {
    pub deposited_collateral: u64,
    pub debt: u64,
}

pub struct LiquidationEngine;

impl LiquidationEngine {
    pub fn liquidate(position: &Position, debt_to_cover: u64, collateral_price: u64, bonus_basis_points: u64) -> Result<u64, String> {
        let bonus = debt_to_cover * bonus_basis_points / 10000;
        let total_required = debt_to_cover + bonus;
        
        // Vulnerable: strict check requires full debt + bonus in collateral
        // Reverts when collateral dropped below bonus threshold, preventing any liquidation
        let collateral_needed = total_required / collateral_price;
        if position.deposited_collateral < collateral_needed {
            return Err("Insufficient collateral for debt + bonus".to_string());
        }
        
        let collateral_to_seize = cmp::min(collateral_needed, position.deposited_collateral);
        
        Ok(collateral_to_seize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_liquidation_reverts_when_underfunded() {
        let pos = Position { deposited_collateral: 50, debt: 1000 };
        // collateral value = 50 * 10 = 500, debt = 1000, bonus = 100
        // total_required = 1100, collateral_needed = 110
        // deposited = 50 < 110, reverts even though some liquidation possible
        let result = LiquidationEngine::liquidate(&pos, 500, 10, 1000);
        assert!(result.is_err());
    }
}