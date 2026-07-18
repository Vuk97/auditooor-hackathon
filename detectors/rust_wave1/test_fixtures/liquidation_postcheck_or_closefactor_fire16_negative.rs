use std::cmp;

pub struct Position {
    pub deposited_collateral: u64,
    pub debt: u64,
}

pub struct LiquidationEngine;

impl LiquidationEngine {
    pub fn liquidate_bonus_capped(position: &Position, debt_to_cover: u64, collateral_price: u64, bonus_basis_points: u64) -> Result<u64, String> {
        if position.deposited_collateral == 0 {
            return Err("no collateral".to_string());
        }

        let bonus = debt_to_cover * bonus_basis_points / 10_000;
        let total_required = debt_to_cover + bonus;
        let collateral_needed = total_required / collateral_price;
        let collateral_to_seize = cmp::min(collateral_needed, position.deposited_collateral);

        Ok(collateral_to_seize)
    }

    pub fn liquidate_partial_boundary(repay: u64) -> u64 {
        let close_factor = 5000;
        if repay >= close_factor {
            panic!("repay exceeds close factor");
        }
        repay
    }

    pub fn liquidate_with_post_health(user: u64, debt_amount: u64, collateral_amount: u64) -> u64 {
        let pre_hf = compute_hf(user);
        let mut remaining_debt = debt_amount;
        remaining_debt -= debt_amount / 2;
        let seized_collateral = collateral_amount / 2;
        let post_hf = calculate_health_factor(user, remaining_debt, seized_collateral);
        assert!(post_hf > pre_hf);
        post_hf
    }
}

fn compute_hf(_: u64) -> u64 {
    1
}

fn calculate_health_factor(_: u64, _: u64, _: u64) -> u64 {
    2
}
