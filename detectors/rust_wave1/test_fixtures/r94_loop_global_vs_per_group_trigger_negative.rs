use soroban_sdk::{contract, contractimpl};
pub struct Group { pub debt: u128 }
#[contract]
pub struct SafeMarket;
#[contractimpl]
impl SafeMarket {
    // OK: compares per-group debt to threshold
    pub fn should_adl(groups: &[Group], threshold: u128, group_idx: usize) -> bool {
        groups[group_idx].debt >= threshold
    }
    // OK: both global and per-group aggregates checked (multi-level)
    pub fn should_deleverage(groups: &[Group], total_debt: u128, global_threshold: u128, per_group_threshold: u128, group_idx: usize) -> bool {
        total_debt >= global_threshold && groups[group_idx].debt >= per_group_threshold
    }
}
