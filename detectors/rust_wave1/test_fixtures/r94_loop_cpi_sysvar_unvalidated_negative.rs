use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    pub fn deposit(sysvar_instructions: u8, amount: u128) {
        // OK: verify sysvar key matches canonical ID before CPI
        require(sysvar_instructions == sysvar::instructions::ID);
        let ctx = CpiContext::new(sysvar_instructions, amount);
        spl_ibc::cpi::set_stake(ctx);
    }
}
mod sysvar { pub mod instructions { pub const ID: u8 = 0u8; } }
pub struct CpiContext;
impl CpiContext { pub fn new(_s: u8, _a: u128) -> Self { Self } }
mod spl_ibc { pub mod cpi { pub fn set_stake(_c: super::super::CpiContext) {} } }
fn require(_: bool) {}
