use soroban_sdk::{contract, contractimpl, Env};
pub struct Ctx;
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    pub fn deposit_len_checked(ctx: Ctx, amount: u128) {
        let remaining_accounts: &[u8] = &[];
        require(remaining_accounts.len() == 3);
        for a in remaining_accounts.iter() {
            spl_ibc::cpi::set_stake(CpiContext::new(a.clone(), remaining_accounts.clone()));
        }
    }

    pub fn deposit_key_checked(ctx: Ctx, amount: u128, expected_guardian: u8) {
        let remaining_accounts: &[u8] = &[];
        require(remaining_accounts[0].key() == expected_guardian);
        spl_ibc::cpi::set_stake(CpiContext::new(remaining_accounts[0], remaining_accounts.clone()));
    }

    pub fn deposit_fully_validated(ctx: Ctx, amount: u128) {
        let remaining_accounts: &[u8] = &[];
        validate_remaining_accounts(remaining_accounts);
        for a in remaining_accounts.iter() {
            spl_ibc::cpi::set_stake(CpiContext::new(a.clone(), remaining_accounts.clone()));
        }
    }
}
pub struct CpiContext;
impl CpiContext { pub fn new(_a: u8, _r: &[u8]) {} }
mod spl_ibc { pub mod cpi { pub fn set_stake(_c: ()) {} } }
fn require(_: bool) {}
fn validate_remaining_accounts(_r: &[u8]) {}
impl u8 { pub fn key(&self) -> u8 { *self } }
