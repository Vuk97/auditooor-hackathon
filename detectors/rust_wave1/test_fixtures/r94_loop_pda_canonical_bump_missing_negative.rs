use soroban_sdk::{contract, contractimpl};
pub struct Pubkey;
impl Pubkey {
    pub fn create_program_address(_s: &[&[u8]], _p: &Pubkey) -> Result<Pubkey, ()> { Ok(Pubkey) }
    pub fn find_program_address(_s: &[&[u8]], _p: &Pubkey) -> (Pubkey, u8) { (Pubkey, 0) }
}
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: canonical bump via find_program_address
    pub fn derive_pda(user: [u8; 32], program_id: Pubkey) -> Pubkey {
        let (pda, _canonical_bump) = Pubkey::find_program_address(&[&user], &program_id);
        pda
    }
    // OK: explicit canonical_bump binding
    pub fn derive_pda_stored(user: [u8; 32], canonical_bump: u8, program_id: Pubkey) -> Pubkey {
        Pubkey::create_program_address(&[&user, &[canonical_bump]], &program_id).unwrap()
    }
}
