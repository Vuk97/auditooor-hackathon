use soroban_sdk::{contract, contractimpl};
pub struct Group { pub debt: u128 }
#[contract]
pub struct Market;
#[contractimpl]
impl Market {
    // BUG: ADL on total_debt (global) while iterating per-group
    pub fn should_adl(groups: &[Group], total_debt: u128, threshold: u128, group_idx: usize) -> bool {
        let _g = &groups[group_idx];
        total_debt >= threshold
    }
}
