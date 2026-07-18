use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeToken;
#[contractimpl]
impl SafeToken {
    // OK: deploy-time binding via require(msg.sender == FACTORY)
    pub fn initialize(_owner: u64, deployer_address: u64) {
        require(caller() == deployer_address);
        let _ = deployer_address;
        let mut owner = 0u64;
        owner = _owner;
        let _ = owner;
    }
}
fn require(_c: bool) {}
fn caller() -> u64 { 0 }
