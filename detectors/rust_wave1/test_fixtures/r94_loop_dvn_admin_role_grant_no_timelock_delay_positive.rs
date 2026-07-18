use soroban_sdk::{contract, contractimpl};
use std::collections::HashSet;
type Address = [u8; 20];
pub struct State { admins: HashSet<Address> }
fn load_state() -> State { State { admins: HashSet::new() } }
fn save_state(_s: &State) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn grant_role(new_admin: Address) {
        let mut state = load_state();
        state.admins.insert(new_admin);
        save_state(&state);
    }
}
