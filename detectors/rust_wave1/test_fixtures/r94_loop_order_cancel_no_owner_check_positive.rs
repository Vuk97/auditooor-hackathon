use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Book;
#[contractimpl]
impl Book {
    // BUG: cancel doesn't verify caller == orders[order_id].owner
    pub fn cancel_order(order_id: u64) {
        let order = orders[order_id as usize];
        orders_remove(order);
    }
}
fn orders_remove(_o: Order) {}
pub struct Order { pub owner: u64 }
#[allow(non_upper_case_globals)]
static mut orders: [Order; 16] = [const { Order { owner: 0 } }; 16];
