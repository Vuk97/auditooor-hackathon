use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeLOB;
#[contractimpl]
impl SafeLOB {
    // OK: non_reentrant guards the order-book mutation
    pub fn place_order(token: Token, from: u64, price: u128, size: u128) {
        non_reentrant();
        token.transfer_from(from, price, size);
        self.orders.insert(size);
    }
}
fn non_reentrant() {}
pub struct Token;
impl Token { fn transfer_from(&self, _f: u64, _p: u128, _s: u128) {} }
impl SafeLOB { fn noop(&mut self) {} }
