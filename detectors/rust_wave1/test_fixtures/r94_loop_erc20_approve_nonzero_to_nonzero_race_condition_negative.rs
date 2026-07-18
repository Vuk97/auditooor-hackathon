use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;
type Address = [u8; 20];
pub struct State { allowances: HashMap<(Address, Address), u128> }
fn get_state() -> State { State { allowances: HashMap::new() } }
fn save_state(_s: &State) {}
#[contract]
pub struct Token;
#[contractimpl]
impl Token {
    // SAFE: requires current_allowance == 0 OR value == 0 before writing
    pub fn approve(owner: Address, spender: Address, value: u128) {
        let mut state = get_state();
        let current_allowance = *state.allowances.get(&(owner, spender)).unwrap_or(&0);
        assert!(value == 0 || current_allowance == 0, "approve: non-zero to non-zero race");
        state.allowances.insert((owner, spender), value);
        save_state(&state);
    }
}
