use soroban_sdk::{contract, contractimpl, Env, Address, BytesN};
#[contract]
pub struct Bridge;
#[contractimpl]
impl Bridge {
    // BUG: single observer role, no proof, no success check
    pub fn mark_inbound(env: Env, observer: Address, tx_hash: BytesN<32>, amount: i128, recipient: Address) {
        require_observer(&env, &observer);
        Self::credit(&env, recipient, amount);
    }
}
impl Bridge { fn credit(_e: &Env, _r: Address, _a: i128) {} }
fn require_observer(_e: &Env, _o: &Address) {}
