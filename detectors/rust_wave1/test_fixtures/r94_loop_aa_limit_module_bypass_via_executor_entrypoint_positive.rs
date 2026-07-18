use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Call { target: Address, value: u64, data: Vec<u8> }
fn transfer(_target: Address, _value: u64) {}
#[contract]
pub struct Wallet;
#[contractimpl]
impl Wallet {
    // BUG: executor entrypoint transfers native value without invoking NativeTokenLimitModule
    pub fn execute_from_executor(c: Call) {
        transfer(c.target, c.value);
    }
}
