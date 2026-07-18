use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Target;
#[contractimpl]
impl Target {
    // BUG: governor OR timelock can set_fees — governor skips delay
    pub fn set_fees(caller: u64, fee: u128) {
        let governor = 1u64;
        let timelock = 2u64;
        let _ = (governor, timelock);
        if !(caller == governor || caller == timelock) { panic!("unauth"); }
        let _ = fee;
    }
}
