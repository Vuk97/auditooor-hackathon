// MOVED from StrategyManager during M2 upgrade

use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeDelegationManager;
#[contractimpl]
impl SafeDelegationManager {
    // reinitializer exists to set the migrated var
    pub fn initialize_v2(delay: u64) {
        let _ = delay;
    }
    pub fn get_withdrawal_delay() -> u64 { 0 }
}
