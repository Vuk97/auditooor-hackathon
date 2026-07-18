use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;

type Address = [u8; 20];
pub struct Grant { total_amount: u128 }
pub struct State { grants: HashMap<Address, Grant> }
fn load_state() -> State { State { grants: HashMap::new() } }
fn save_state(_s: &State) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn revoke_grant(beneficiary: Address) {
        let mut state = load_state();
        if let Some(mut grant) = state.grants.remove(&beneficiary) {
            grant.total_amount = 0;
        }
        save_state(&state);
    }
}
