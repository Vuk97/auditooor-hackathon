use soroban_sdk::{contract, contractimpl};

pub struct State { _CACHED_CHAIN_ID: u64 }
fn load_state() -> State { State { _CACHED_CHAIN_ID: 0 } }
fn save_state(_s: &State) {}
fn rebuild_domain_separator(_s: &mut State) {}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn initialize() {
        let mut state = load_state();
        let current_chain_id: u64 = 1;
        state._CACHED_CHAIN_ID = current_chain_id;
        rebuild_domain_separator(&mut state);
        save_state(&state);
    }
}
