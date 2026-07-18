use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn accrue_interest(_vault: Address) {}
fn save_debt(_who: Address, _amt: u64) {}
#[contract]
pub struct CDPVault;
#[contractimpl]
impl CDPVault {
    // BUG: accrues interest on every tiny borrow without min-amount / cooldown
    pub fn borrow(vault: Address, who: Address, amount: u64) {
        accrue_interest(vault);
        save_debt(who, amount);
    }
}
