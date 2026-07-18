use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeFactory;
#[contractimpl]
impl SafeFactory {
    // OK: rent-exempt minimum_balance used as lamports
    pub fn spawn(payer: Pubkey, new_account: Pubkey, space: u64) {
        let lamports = Rent::get().unwrap().minimum_balance(space);
        system_instruction::create_account(&payer, &new_account, lamports, space, &Pubkey);
    }
}
pub struct Pubkey;
pub struct Rent;
impl Rent {
    pub fn get() -> Result<Self, ()> { Ok(Rent) }
    pub fn minimum_balance(&self, _s: u64) -> u64 { 0 }
}
mod system_instruction {
    pub fn create_account(_p: &super::Pubkey, _n: &super::Pubkey, _l: u64, _s: u64, _o: &super::Pubkey) {}
}
