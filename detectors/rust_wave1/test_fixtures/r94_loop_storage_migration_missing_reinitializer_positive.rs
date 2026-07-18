// MOVED from StrategyManager during M2 upgrade
// Was in StrategyManager.sol prior to M2

use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct DelegationManager;
#[contractimpl]
impl DelegationManager {
    pub fn get_withdrawal_delay() -> u64 { 0 }
}
