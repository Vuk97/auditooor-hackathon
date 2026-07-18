// Positive: permissionless intake with no fee/rate-limit/cap.
use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct DataRequests;

#[contractimpl]
impl DataRequests {
    pub fn post_request(env: Env, caller: Address, request_id: u64) {
        // BUG: no fee, no rate-limit, no per-caller cap.
        Self::get_queue(&env).push_back(request_id);
    }
}

impl DataRequests {
    fn get_queue(_e: &Env) -> QueueMock { QueueMock }
}
pub struct QueueMock;
impl QueueMock { pub fn push_back(&self, _id: u64) {} }
