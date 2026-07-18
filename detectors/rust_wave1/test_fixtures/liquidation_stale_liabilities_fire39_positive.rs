use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];

pub struct Borrower {
    pub debt: u64,
    pub collateral: u64,
}

fn borrow_balance_stored(_user: u64) -> u128 {
    100
}

fn load_borrower(_who: Address) -> Borrower {
    Borrower { debt: 1000, collateral: 500 }
}

fn save_borrower(_b: &Borrower) {}
fn stability_pool_available() -> u64 { 600 }
fn seize_collateral(_amount: u64) {}
fn require(_ok: bool) {}

#[contract]
pub struct UnsafeLiquidator;

#[contractimpl]
impl UnsafeLiquidator {
    pub fn liquidate_with_stored_liabilities(user: u64) -> bool {
        let stored_debt = borrow_balance_stored(user);
        stored_debt > 0
    }

    pub fn liquidate_bonus_strict(debt: u128, bonus_bps: u128, collateral: u128) -> u128 {
        let required = debt + debt * bonus_bps / 10_000;
        require(required <= collateral);
        required
    }

    pub fn liquidate_partial_pool(who: Address) {
        let mut borrower = load_borrower(who);
        let pool_available = stability_pool_available();
        borrower.debt -= pool_available.min(borrower.debt);
        seize_collateral(borrower.collateral);
        save_borrower(&borrower);
    }
}
