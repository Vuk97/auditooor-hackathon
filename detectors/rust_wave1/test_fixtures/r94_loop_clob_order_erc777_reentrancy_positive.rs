use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct LOB;
#[contractimpl]
impl LOB {
    // BUG: transfer before order-book state update, no reentrancy guard
    pub fn place_order(token: Token, from: u64, price: u128, size: u128) {
        token.transfer_from(from, price, size);
        self.orders.insert(size);
    }
}
pub struct Token;
impl Token { fn transfer_from(&self, _f: u64, _p: u128, _s: u128) {} }
impl LOB { fn noop(&mut self) {} }
