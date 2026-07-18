use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: uses non_reentrant guard before royalty call
    pub fn buy(nft: u64, price: u128) -> u128 {
        non_reentrant();
        let royalty_receiver = royalty_info(nft).0;
        royalty_receiver.call(price / 100);
        price
    }
}
fn non_reentrant() {}
fn royalty_info(_n: u64) -> (Receiver, u128) { (Receiver, 0) }
struct Receiver;
impl Receiver { fn call(&self, _v: u128) {} }
