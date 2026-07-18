use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    pub fn deposit(sysvar_instructions: u8, amount: u128) {
        // BUG: use sysvar_instructions in CPI without verifying it equals the canonical ID
        let ctx = CpiContext::new(sysvar_instructions, amount);
        spl_ibc::cpi::set_stake(ctx);
    }
}
pub struct CpiContext;
impl CpiContext { pub fn new(_s: u8, _a: u128) -> Self { Self } }
mod spl_ibc { pub mod cpi { pub fn set_stake(_c: super::super::CpiContext) {} } }
