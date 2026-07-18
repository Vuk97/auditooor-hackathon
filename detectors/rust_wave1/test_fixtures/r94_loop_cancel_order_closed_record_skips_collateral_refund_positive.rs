use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Book;
#[contractimpl]
impl Book {
    // BUG: closed branch deletes record without refunding collateral
    pub fn cancel_order(order_id: u64, record_status: u32) {
        if record_status == Closed {
            self.orders.remove(&order_id);
        }
    }
}
const Closed: u32 = 3;
impl Book { fn noop(&mut self) {} }
