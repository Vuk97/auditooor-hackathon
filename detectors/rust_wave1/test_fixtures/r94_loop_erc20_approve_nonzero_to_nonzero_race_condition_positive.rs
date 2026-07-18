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
    // BUG: writes new allowance without requiring prior allowance == 0
    pub fn approve(owner: Address, spender: Address, value: u128) {
        let mut state = get_state();
        state.allowances.insert((owner, spender), value);
        save_state(&state);
    }
}
