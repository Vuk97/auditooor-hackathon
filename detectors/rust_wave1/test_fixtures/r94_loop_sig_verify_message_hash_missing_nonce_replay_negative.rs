use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn update_keys(message_hash: [u8; 32], sig: Vec<u8>, nonce: u64) {
        let signer = ecdsa_recover(message_hash, &sig);
        let mut state = load_state();
        assert!(state.current_nonce == nonce, "bad nonce");
        state.current_nonce = state.current_nonce + 1;
        save_state(&state);
        let _ = signer;
    }
}

pub struct State { current_nonce: u64 }
fn load_state() -> State { State { current_nonce: 0 } }
fn save_state(_s: &State) {}
fn ecdsa_recover(_h: [u8; 32], _s: &[u8]) -> [u8; 20] { [0; 20] }
