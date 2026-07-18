use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeLoan;
#[contractimpl]
impl SafeLoan {
    // OK: LTV uses principal + accrued_interest in the denominator
    pub fn liquidate(position_amount: u128, position_size: u128) -> bool {
        let debt_with_interest = position_size + accrued_interest(position_size);
        if position_amount * 1000 / debt_with_interest > 900 {
            return false;
        }
        do_liquidate();
        true
    }
}
fn accrued_interest(_p: u128) -> u128 { 0 }
fn do_liquidate() {}
