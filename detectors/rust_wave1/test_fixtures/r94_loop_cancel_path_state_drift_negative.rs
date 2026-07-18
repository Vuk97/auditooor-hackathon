use soroban_sdk::{contract, contractimpl};
pub struct State { pub cancelled_partial: bool }
#[contract]
pub struct SafeRedeemer;
#[contractimpl]
impl SafeRedeemer {
    // OK: updates stakes + reinserts into sorted before early-return
    pub fn redeem(state: &mut State, new_debt: u128, min_debt: u128) -> u64 {
        if new_debt < min_debt {
            state.cancelled_partial = true;
            update_stakes();
            reinsert_into_sorted();
            apply_pending_rewards();
            return 0;
        }
        1
    }
}
fn update_stakes() {}
fn reinsert_into_sorted() {}
fn apply_pending_rewards() {}
