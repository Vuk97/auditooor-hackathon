use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Jetton;
#[contractimpl]
impl Jetton {
    // BUG: on burn_notification, updates total_supply without sender check
    pub fn recv_internal(sender_address: u64, amount: u128, op: u32, total_supply: &mut u128) {
        let burn_notification_op = 0x7bdd97de;
        if op == burn_notification_op {
            *total_supply -= amount;
        }
    }
}
