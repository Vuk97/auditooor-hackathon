use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBook;
#[contractimpl]
impl SafeBook {
    // OK: refunds collateral before deleting record
    pub fn cancel_order(order_id: u64, record_status: u32) {
        if record_status == Closed {
            refund_collateral(order_id);
            self.orders.remove(&order_id);
        }
    }
}
fn refund_collateral(_o: u64) {}
const Closed: u32 = 3;
impl SafeBook { fn noop(&mut self) {} }
