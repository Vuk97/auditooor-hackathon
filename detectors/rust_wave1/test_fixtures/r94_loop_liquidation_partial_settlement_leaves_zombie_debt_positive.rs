use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Borrower { debt: u64, collateral: u64 }
fn load_borrower(_who: Address) -> Borrower { Borrower { debt: 1000, collateral: 500 } }
fn save_borrower(_b: &Borrower) {}
fn stability_pool_available() -> u64 { 600 }
fn seize_collateral(_amt: u64) {}
#[contract]
pub struct LiquidationManager;
#[contractimpl]
impl LiquidationManager {
    // BUG: reduces debt by SP-available, but never zeros debt when pool insufficient
    pub fn liquidate(who: Address) {
        let mut b = load_borrower(who);
        let pool = stability_pool_available();
        b.debt -= pool.min(b.debt);  // partial settlement
        seize_collateral(b.collateral);
        save_borrower(&b);
    }
}
