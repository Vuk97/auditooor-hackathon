use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Unlock;
#[contractimpl]
impl Unlock {
    // BUG: vec![items_len] is a one-element vec, not a vec of items_len elements
    pub fn init_compact_unlock(items_len: u64) {
        let items = vec![items_len];
        let _slice = &items[0..1];
    }
    // BUG: vec![computed_count]
    pub fn alloc(computed_count: u64) {
        let items = vec![computed_count];
        let _ = items;
    }
}
