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
    // Uses SPOT for health check (marks solvent)
    pub fn check_solvent(borrower: &BorrowerAccount) -> bool {
        let collateral_value = borrower.collateral_amount.saturating_mul(borrower.collateral_price.spot);
        let borrow_value = borrower.borrow_amount.saturating_mul(100);
        collateral_value >= borrow_value
    }

    // Uses EMA for liquidation eligibility (lagging, lower price)
    pub fn can_liquidate(borrower: &BorrowerAccount, min_health_ratio: u64) -> bool {
        let collateral_value = borrower.collateral_amount.saturating_mul(borrower.collateral_price.ema); // BUG: EMA instead of spot
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
    // EMA lag scenario: spot recovered to 100, EMA still at 60
    let borrower = BorrowerAccount {
        collateral_amount: 1000,
        borrow_amount: 500,
        collateral_price: Price { spot: 100, ema: 60 },
    };
    // check_solvent says true (spot*1000 = 100000 >= 50000)
    // can_liquidate says true (ema*1000 = 60000 < 75000 at 150% ratio)
    let result = LiquidationEngine::attempt_liquidation(&borrower, 150);
    assert!(result.is_ok(), "BUG: solvent borrower gets liquidated due to EMA lag");
    println!("Vulnerable: EMA used for liquidation threshold, spot for solvency check");
}