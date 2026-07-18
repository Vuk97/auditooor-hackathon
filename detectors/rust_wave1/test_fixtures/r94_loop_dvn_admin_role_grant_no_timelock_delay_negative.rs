use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;
type Address = [u8; 20];
pub struct State { pending_admin: HashMap<Address, u64>, admins: std::collections::HashSet<Address> }
fn load_state() -> State { State { pending_admin: HashMap::new(), admins: std::collections::HashSet::new() } }
fn save_state(_s: &State) {}
fn now() -> u64 { 1000 }
const GRANT_DELAY: u64 = 86400;
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn grant_role(new_admin: Address) {
        let mut state = load_state();
        let ready_at = now() + GRANT_DELAY;
        state.pending_admin.insert(new_admin, ready_at);
        save_state(&state);
    }
}
