use std::cmp;
use std::collections::HashMap;

pub struct Order {
    pub offer: Vec<u64>,
    pub consideration: Vec<u64>,
}

pub struct ClearingHouse {
    collateral_nft: u64,
    settlement_token: u64,
    authorized_clearing_nfts: HashMap<u64, bool>,
}

impl ClearingHouse {
    pub fn validate_liquidation_order(&self, order: &Order) -> Result<(), &'static str> {
        if order.offer.len() != 1 || order.offer[0] != self.collateral_nft {
            return Err("bad offer");
        }
        if order.consideration.is_empty() || order.consideration[0] != self.settlement_token {
            return Err("bad settlement token");
        }
        if order.consideration.len() > 1 {
            for extra in &order.consideration[1..] {
                if !self.authorized_clearing_nfts.contains_key(extra) {
                    return Err("unauthorized extra consideration");
                }
            }
        }
        Ok(())
    }
}

pub struct Position {
    pub collateral: u64,
    pub debt: u64,
}

pub struct LiquidationResult {
    pub collateral_seized: u64,
    pub debt_repaid: u64,
}

fn ceil_div(a: u64, b: u64) -> u64 {
    (a + b - 1) / b
}

pub fn liquidate_position(
    position: &Position,
    collateral_price: u64,
    debt_price: u64,
    liquidation_bonus: u64,
) -> Option<LiquidationResult> {
    let debt_value = position.debt.checked_mul(debt_price)?;
    let collateral_numerator = debt_value.checked_mul(10_000 + liquidation_bonus)?;
    let collateral_to_seize = collateral_numerator
        .checked_div(collateral_price)?
        .checked_div(10_000)?;
    let debt_to_repay = ceil_div(debt_value, debt_price);

    Some(LiquidationResult {
        collateral_seized: cmp::min(collateral_to_seize, position.collateral),
        debt_repaid: cmp::min(debt_to_repay, position.debt),
    })
}

pub struct Borrower {
    pub collateral: u128,
    pub debt: u128,
}

pub struct HealthState {
    pub live_price: u128,
}

fn refresh_health_state(_borrower: &Borrower) -> HealthState {
    HealthState { live_price: 100 }
}

pub fn is_liquidatable(borrower: &Borrower) -> bool {
    let health = refresh_health_state(borrower);
    let collateral_value = borrower.collateral * health.live_price / 1_000_000;
    collateral_value < borrower.debt
}
