use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];

pub struct Borrower {
    pub debt: u64,
    pub collateral: u64,
}

fn accrue_interest() {}
fn borrow_balance_stored(_user: u64) -> u128 { 100 }
fn load_borrower(_who: Address) -> Borrower {
    Borrower { debt: 1000, collateral: 500 }
}
fn save_borrower(_b: &Borrower) {}
fn stability_pool_available() -> u64 { 1200 }
fn seize_collateral(_amount: u64) {}
fn record_bad_debt(_amount: u64) {}

#[contract]
pub struct SafeLiquidator;

#[contractimpl]
impl SafeLiquidator {
    pub fn liquidate_with_fresh_liabilities(user: u64) -> bool {
        accrue_interest();
        let stored_debt = borrow_balance_stored(user);
        stored_debt > 0
    }

    pub fn liquidate_bonus_capped(debt: u128, bonus_bps: u128, collateral: u128) -> u128 {
        let required = debt + debt * bonus_bps / 10_000;
        let capped_seize = required.min(collateral);
        capped_seize
    }

    pub fn liquidate_partial_pool_with_cleanup(who: Address) {
        let mut borrower = load_borrower(who);
        let pool_available = stability_pool_available();
        if pool_available < borrower.debt {
            record_bad_debt(borrower.debt - pool_available);
        }
        borrower.debt -= pool_available.min(borrower.debt);
        borrower.debt = 0;
        seize_collateral(borrower.collateral);
        save_borrower(&borrower);
    }
}
