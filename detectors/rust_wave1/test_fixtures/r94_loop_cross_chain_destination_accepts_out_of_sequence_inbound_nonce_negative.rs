use soroban_sdk::{contract, contractimpl};

pub struct Origin { nonce: u64 }
pub struct State { last_nonce: u64 }
fn load_state() -> State { State { last_nonce: 0 } }
fn save_state(_s: &State) {}
fn process_message(_n: u64) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn lz_receive(origin: Origin, payload: Vec<u8>) {
        let nonce = origin.nonce;
        let mut state = load_state();
        assert!(nonce == state.last_nonce + 1, "out-of-sequence nonce");
        state.last_nonce = nonce;
        save_state(&state);
        process_message(nonce);
        let _ = payload;
    }
}
