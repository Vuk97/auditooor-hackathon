use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Call { target: Address, value: u64, data: Vec<u8> }
fn transfer(_target: Address, _value: u64) {}
fn native_token_limit_check(_v: u64) {}
fn pre_execution_hook() {}
#[contract]
pub struct Wallet;
#[contractimpl]
impl Wallet {
    // SAFE: runs pre_execution_hook + native_token_limit_check before the transfer
    pub fn execute_from_executor(c: Call) {
        pre_execution_hook();
        native_token_limit_check(c.value);
        transfer(c.target, c.value);
    }
}
