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
    // SAFE: requires SP has enough to fully cover debt before seizing collateral
    pub fn liquidate(who: Address) {
        let mut b = load_borrower(who);
        let pool_available = stability_pool_available();
        assert!(pool_available >= b.debt, "stability pool insufficient");
        b.debt -= pool_available.min(b.debt);
        b.debt = 0;
        seize_collateral(b.collateral);
        save_borrower(&b);
    }
}
