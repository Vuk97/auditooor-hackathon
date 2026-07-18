use soroban_sdk::{contract, contractimpl};
use std::collections::HashSet;
type Address = [u8; 20];
pub struct State { blacklist: HashSet<Address> }
fn load_state() -> State { State { blacklist: HashSet::new() } }
fn save_state(_s: &State) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn sweep(target: Address) {
        let mut state = load_state();
        state.blacklist.insert(target);
        save_state(&state);
    }
}
