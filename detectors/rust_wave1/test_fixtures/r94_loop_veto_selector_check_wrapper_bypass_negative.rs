use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeCouncil;
#[contractimpl]
impl SafeCouncil {
    // OK: recurses via decode_multicall before selector check
    pub fn veto(action: u64, selector: u32) -> bool {
        let _ = decode_multicall(action);
        if selector == 0xdeadbeef {
            return false;
        }
        true
    }
}
fn decode_multicall(_a: u64) -> bool { false }
