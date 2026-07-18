use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeCosmosPrecompile;
#[contractimpl]
impl SafeCosmosPrecompile {
    // OK: sibling drain fn exists
    pub fn execute_cosmos(queue: &mut Vec<u64>, req: u64) {
        queue.push(req);
    }
    pub fn flush_queue(queue: &mut Vec<u64>) {
        queue.drain(..);
    }
}
