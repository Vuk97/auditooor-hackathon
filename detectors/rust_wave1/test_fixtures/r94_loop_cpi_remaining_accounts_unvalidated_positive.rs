use soroban_sdk::{contract, contractimpl, Env};
pub struct Ctx;
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    pub fn deposit(ctx: Ctx, amount: u128) {
        let remaining_accounts: &[u8] = &[];
        // BUG: iterate remaining_accounts with no length check / no validation
        for a in remaining_accounts.iter() {
            spl_ibc::cpi::set_stake(CpiContext::new(a.clone(), remaining_accounts.clone()));
        }
    }
}
pub struct CpiContext;
impl CpiContext { pub fn new(_a: u8, _r: &[u8]) {} }
mod spl_ibc { pub mod cpi { pub fn set_stake(_c: ()) {} } }
