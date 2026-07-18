use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn transfer_from(_from: Address, _to: Address, _amt: u64) {}
pub struct State { total_deposits: u64 }
fn get_state() -> State { State { total_deposits: 0 } }
fn save_state(_s: &State) {}
fn balances_add(_user: Address, _amt: u64) {}
#[contract]
pub struct Lender;
#[contractimpl]
impl Lender {
    // BUG: credits parameter amount after transfer_from without a balance-delta
    pub fn deposit(user: Address, amount: u64) {
        transfer_from(user, [0; 20], amount);
        let mut state = get_state();
        state.total_deposits += amount;
        balances_add(user, amount);
        save_state(&state);
    }
}
