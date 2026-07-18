use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Price {
    pub spot: u64,
    pub ema: u64,
}

pub struct BorrowerAccount {
    pub collateral_amount: u64,
    pub borrow_amount: u64,
    pub collateral_price: Price,
}

pub struct LiquidationEngine;

impl LiquidationEngine {
    pub fn check_solvent(borrower: &BorrowerAccount) -> bool {
        let collateral_value = borrower.collateral_amount.saturating_mul(borrower.collateral_price.spot);
        let borrow_value = borrower.borrow_amount.saturating_mul(100); // normalized
        collateral_value >= borrow_value
    }

    pub fn can_liquidate(borrower: &BorrowerAccount, min_health_ratio: u64) -> bool {
        let collateral_value = borrower.collateral_amount.saturating_mul(borrower.collateral_price.spot);
        let required_collateral = borrower.borrow_amount.saturating_mul(min_health_ratio);
        collateral_value < required_collateral
    }

    pub fn attempt_liquidation(borrower: &BorrowerAccount, min_health_ratio: u64) -> Result<u64, &'static str> {
        if !Self::check_solvent(borrower) {
            return Err("borrower already insolvent by spot");
        }
        if !Self::can_liquidate(borrower, min_health_ratio) {
            return Err("borrower is healthy, cannot liquidate");
        }
        let seized = borrower.collateral_amount / 2;
        Ok(seized)
    }
}

fn main() {
    let borrower = BorrowerAccount {
        collateral_amount: 1000,
        borrow_amount: 500,
        collateral_price: Price { spot: 100, ema: 80 },
    };
    let result = LiquidationEngine::attempt_liquidation(&borrower, 150);
    assert!(result.is_err(), "healthy borrower should not be liquidated");
    println!("Clean: spot price used consistently, no EMA lag exploit");
}