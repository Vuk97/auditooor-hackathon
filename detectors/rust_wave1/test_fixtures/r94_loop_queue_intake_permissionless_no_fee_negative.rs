// Negative: intake charges a fee OR has a rate-limit OR per-caller cap.
use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct SafeDataRequests;

#[contractimpl]
impl SafeDataRequests {
    // OK: fee charged
    pub fn post_request_with_fee(env: Env, caller: Address, request_id: u64, fee: i128) {
        Self::charge_fee(&env, caller.clone(), fee);
        Self::get_queue(&env).push_back(request_id);
    }
    // OK: rate-limit
    pub fn post_request_rate_limited(env: Env, caller: Address, request_id: u64) {
        let cooldown = Self::get_cooldown(&env, &caller);
        require(env.ledger().sequence() > cooldown);
        Self::get_queue(&env).push_back(request_id);
    }
    // OK: per-caller cap
    pub fn post_request_capped(env: Env, caller: Address, request_id: u64) {
        let pending_count = Self::get_pending_count(&env, &caller);
        require(pending_count < 100);
        Self::get_queue(&env).push_back(request_id);
    }
}
impl SafeDataRequests {
    fn charge_fee(_e: &Env, _u: Address, _f: i128) {}
    fn get_queue(_e: &Env) -> QueueMock { QueueMock }
    fn get_cooldown(_e: &Env, _u: &Address) -> u32 { 0 }
    fn get_pending_count(_e: &Env, _u: &Address) -> u32 { 0 }
}
pub struct QueueMock;
impl QueueMock { pub fn push_back(&self, _id: u64) {} }
fn require(_: bool) {}
