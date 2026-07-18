use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];
fn balance_of(_who: Address) -> u128 { 10_000 }
fn self_addr() -> Address { [0; 20] }
fn transfer(_to: Address, _amt: u128) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn release(user: Address, shares: u128, total_shares: u128) {
        let balance = balance_of(self_addr());
        let payout = shares * balance / total_shares;
        transfer(user, payout);
    }
}
