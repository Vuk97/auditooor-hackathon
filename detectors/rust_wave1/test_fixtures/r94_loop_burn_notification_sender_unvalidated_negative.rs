use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeJetton;
#[contractimpl]
impl SafeJetton {
    // OK: asserts sender_address == jetton_master before supply update
    pub fn recv_internal(sender_address: u64, amount: u128, op: u32, total_supply: &mut u128, jetton_master: u64) {
        let burn_notification_op = 0x7bdd97de;
        if op == burn_notification_op {
            require(sender_address == jetton_master);
            *total_supply -= amount;
        }
    }
}
fn require(_: bool) {}
