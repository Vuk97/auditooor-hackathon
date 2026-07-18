use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Token;
impl Token {
    fn approve(&self, _spender: Address, _amount: u128) {}
}
fn load_token(_a: Address) -> Token { Token }
fn router_swap(_t: Address, _amount: u128) {}
#[contract]
pub struct Integrator;
#[contractimpl]
impl Integrator {
    // BUG: token.approve(router, amount) without resetting to zero first
    pub fn swap(router: Address, usdt: Address, amount: u128) {
        let token = load_token(usdt);
        token.approve(router, amount);
        router_swap(usdt, amount);
    }
}
