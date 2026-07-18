use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeTarget;
#[contractimpl]
impl SafeTarget {
    // OK: only timelock can set_fees (governor must go through it)
    pub fn set_fees(caller: u64, fee: u128) {
        let timelock = 2u64;
        if caller != timelock { panic!("unauth"); }
        let _ = fee;
    }
}
