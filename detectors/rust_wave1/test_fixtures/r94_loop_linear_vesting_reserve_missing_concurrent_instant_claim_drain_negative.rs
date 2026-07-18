use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];
fn balance_of(_who: Address) -> u128 { 1_000_000 }
fn self_addr() -> Address { [0; 20] }
fn schedule_linear_unlock_schedule(_a: u128) {}
pub struct State { total_reserved: u128 }
fn load_state() -> State { State { total_reserved: 0 } }
fn save_state(_s: &State) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn transmute_linear(amount: u128) {
        let mut state = load_state();
        assert!(balance_of(self_addr()) >= state.total_reserved + amount, "insufficient unreserved output");
        state.total_reserved += amount;
        save_state(&state);
        schedule_linear_unlock_schedule(amount);
    }
}
