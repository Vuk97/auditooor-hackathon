use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Factory;
#[contractimpl]
impl Factory {
    // BUG: create_account with no minimum_balance call
    pub fn spawn(payer: Pubkey, new_account: Pubkey, space: u64) {
        let lamports: u64 = 100; // arbitrary, not rent-exempt
        system_instruction::create_account(&payer, &new_account, lamports, space, &Pubkey);
    }
}
pub struct Pubkey;
mod system_instruction {
    pub fn create_account(_p: &super::Pubkey, _n: &super::Pubkey, _l: u64, _s: u64, _o: &super::Pubkey) {}
}
