use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn transfer_from(_from: Address, _to: Address, _amt: u64) {}
fn balance_of(_token: Address, _who: Address) -> u64 { 0 }
pub struct State { total_deposits: u64 }
fn get_state() -> State { State { total_deposits: 0 } }
fn save_state(_s: &State) {}
#[contract]
pub struct Lender;
#[contractimpl]
impl Lender {
    // SAFE: measures balance delta around transfer_from, credits actual_received
    pub fn deposit(token: Address, user: Address, amount: u64) {
        let balance_before = balance_of(token, [0; 20]);
        transfer_from(user, [0; 20], amount);
        let balance_after = balance_of(token, [0; 20]);
        let actual_received = balance_after - balance_before;
        let mut state = get_state();
        state.total_deposits += actual_received;
        save_state(&state);
    }
}
