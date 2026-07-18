use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: fetches royalty_receiver from ERC2981 and calls it without reentrancy guard
    pub fn buy(nft: u64, price: u128) -> u128 {
        let royalty_receiver = royalty_info(nft).0;
        royalty_receiver.call(price / 100);
        price
    }
}
fn royalty_info(_n: u64) -> (Receiver, u128) { (Receiver, 0) }
struct Receiver;
impl Receiver { fn call(&self, _v: u128) {} }
