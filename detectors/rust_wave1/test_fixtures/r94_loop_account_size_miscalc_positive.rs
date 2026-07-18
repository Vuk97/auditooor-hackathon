use soroban_sdk::{contract, contractimpl};
pub struct Pubkey;
mod system_instruction {
    pub fn create_account(_p: &super::Pubkey, _n: &super::Pubkey, _l: u64, _s: u64, _o: &super::Pubkey) {}
}
#[contract]
pub struct Factory;
#[contractimpl]
impl Factory {
    // BUG: hardcoded 96 — no size_of::<State>() or State::LEN anywhere in file
    pub fn spawn(payer: Pubkey, new_account: Pubkey) {
        system_instruction::create_account(&payer, &new_account, 1_000_000, 96, &Pubkey);
    }
}
