use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBook;
#[contractimpl]
impl SafeBook {
    // OK: verify caller == order.owner before cancel
    pub fn cancel_order(order_id: u64, caller: u64) {
        let order = orders[order_id as usize];
        require(caller == order.owner);
        orders_remove(order);
    }
}
fn orders_remove(_o: Order) {}
fn require(_c: bool) {}
pub struct Order { pub owner: u64 }
#[allow(non_upper_case_globals)]
static mut orders: [Order; 16] = [const { Order { owner: 0 } }; 16];
