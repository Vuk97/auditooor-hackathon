use soroban_sdk::{contract, contractimpl};
pub struct Pubkey;
mod system_instruction {
    pub fn create_account(_p: &super::Pubkey, _n: &super::Pubkey, _l: u64, _s: u64, _o: &super::Pubkey) {}
}
pub struct State { _padding: [u8; 128] }
impl State { pub const LEN: u64 = std::mem::size_of::<State>() as u64; }
#[contract]
pub struct Factory;
#[contractimpl]
impl Factory {
    // OK: State::LEN / size_of::<State>() used
    pub fn spawn(payer: Pubkey, new_account: Pubkey) {
        let space = std::mem::size_of::<State>() as u64;
        system_instruction::create_account(&payer, &new_account, 1_000_000, space, &Pubkey);
    }
}
