use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;

type Address = [u8; 20];
pub struct Claim { amount: u128, released: u128 }
pub struct State { claims: HashMap<Address, Claim> }
fn load_state() -> State { State { claims: HashMap::new() } }
fn save_state(_s: &State) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn update_vesting(user: Address, new_amount: u128) {
        let mut state = load_state();
        if let Some(claim) = state.claims.get_mut(&user) {
            claim.amount = new_amount;
            claim.released = 0;
        }
        save_state(&state);
    }
}
