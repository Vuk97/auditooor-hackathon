use soroban_sdk::{contract, contractimpl};
pub struct Pubkey;
impl Pubkey {
    pub fn create_program_address(_s: &[&[u8]], _p: &Pubkey) -> Result<Pubkey, ()> { Ok(Pubkey) }
    pub fn find_program_address(_s: &[&[u8]], _p: &Pubkey) -> (Pubkey, u8) { (Pubkey, 0) }
}
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: create_program_address without find_program_address / canonical-bump binding
    pub fn derive_pda(user: [u8; 32], bump: u8, program_id: Pubkey) -> Pubkey {
        Pubkey::create_program_address(&[&user, &[bump]], &program_id).unwrap()
    }
}
