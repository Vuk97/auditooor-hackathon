use soroban_sdk::{contract, contractimpl};
pub struct State { pub cancelled_partial: bool }
#[contract]
pub struct Redeemer;
#[contractimpl]
impl Redeemer {
    // BUG: sets cancelled_partial = true and returns without update_stakes / reinsert
    pub fn redeem(state: &mut State, new_debt: u128, min_debt: u128) -> u64 {
        if new_debt < min_debt {
            state.cancelled_partial = true;
            return 0;
        }
        1
    }
}
