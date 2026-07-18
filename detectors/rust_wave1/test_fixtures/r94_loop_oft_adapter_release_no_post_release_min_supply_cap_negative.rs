use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];
pub struct Token;
impl Token {
    fn transfer(&self, _to: Address, _amt: u128) {}
}
fn load_token() -> Token { Token }
fn adapter_balance_after_transfer(_amt: u128) -> u128 { 1000 }

const MAX_PER_MESSAGE: u128 = 1_000_000;
const MIN_RESERVE: u128 = 100;

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn lz_receive(recipient: Address, amount: u128) {
        assert!(amount <= MAX_PER_MESSAGE, "per-message cap");
        let balance_after = adapter_balance_after_transfer(amount);
        assert!(balance_after >= MIN_RESERVE, "below min_reserve");
        let token = load_token();
        token.transfer(recipient, amount);
    }
}
