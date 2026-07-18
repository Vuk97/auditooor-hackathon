use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn accrue_interest(_vault: Address) {}
fn save_debt(_who: Address, _amt: u64) {}
const MIN_BORROW_AMOUNT: u64 = 1_000_000;
#[contract]
pub struct CDPVault;
#[contractimpl]
impl CDPVault {
    // SAFE: enforces a min_borrow_amount floor before accruing interest
    pub fn borrow(vault: Address, who: Address, amount: u64) {
        assert!(amount >= MIN_BORROW_AMOUNT, "amount below MIN_BORROW_AMOUNT");
        accrue_interest(vault);
        save_debt(who, amount);
    }
}
