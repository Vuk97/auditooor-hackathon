use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Council;
#[contractimpl]
impl Council {
    // BUG: checks outer selector only, no recursion into multicall
    pub fn veto(action: u64, selector: u32) -> bool {
        if selector == 0xdeadbeef {
            return false;
        }
        true
    }
}
