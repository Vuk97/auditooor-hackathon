use soroban_sdk::{contract, contractimpl};
pub struct Entry { operator_id: u64, utilization: u64 }
fn load_operator_heap() -> Vec<Entry> { Vec::new() }
fn send_to_operator(_id: u64, _amt: u64) {}
#[contract]
pub struct Allocator;
#[contractimpl]
impl Allocator {
    // SAFE: skips tombstones where operator_id == 0
    pub fn allocate_deposits(total: u64) {
        let heap = load_operator_heap();
        for entry in heap.iter() {
            if entry.operator_id == 0 {
                continue;
            }
            let alloc = total / entry.utilization;
            send_to_operator(entry.operator_id, alloc);
        }
    }
}
