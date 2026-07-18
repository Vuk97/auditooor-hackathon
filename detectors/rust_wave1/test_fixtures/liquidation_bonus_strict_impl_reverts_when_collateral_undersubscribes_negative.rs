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
        
        // Clean: allow partial liquidation, cap at available collateral
        let collateral_to_seize = cmp::min(total_required / collateral_price, position.deposited_collateral);
        
        if collateral_to_seize == 0 {
            return Err("No collateral to seize".to_string());
        }
        
        // Verify we can cover at least the debt (not strict bonus requirement)
        let collateral_value = collateral_to_seize * collateral_price;
        if collateral_value < debt_to_cover {
            return Err("Insufficient collateral value for debt".to_string());
        }
        
        Ok(collateral_to_seize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partial_liquidation_allowed() {
        let pos = Position { deposited_collateral: 100, debt: 1000 };
        let result = LiquidationEngine::liquidate(&pos, 500, 10, 1000); // 10% bonus
        assert!(result.is_ok());
    }
}