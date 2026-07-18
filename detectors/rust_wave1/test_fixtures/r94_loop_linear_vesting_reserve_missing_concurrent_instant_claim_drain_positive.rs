use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];
fn balance_of(_who: Address) -> u128 { 1_000_000 }
fn self_addr() -> Address { [0; 20] }
fn schedule_linear_unlock_schedule(_a: u128) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn transmute_linear(amount: u128) {
        assert!(balance_of(self_addr()) >= amount, "insufficient output");
        schedule_linear_unlock_schedule(amount);
    }
}
