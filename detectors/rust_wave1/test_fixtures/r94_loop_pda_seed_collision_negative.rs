use soroban_sdk::{contract, contractimpl};
pub struct Pubkey;
impl Pubkey { pub fn find_program_address(_s: &[&[u8]], _p: &Pubkey) -> (Pubkey, u8) { (Pubkey, 0) } }
#[contract]
pub struct SafeRegistry;
#[contractimpl]
impl SafeRegistry {
    // OK: literal separator byte between variable slices
    pub fn register(name: String, symbol: String, program_id: Pubkey) -> Pubkey {
        let seeds: &[&[u8]] = &[name.as_bytes(), b"|", symbol.as_bytes()];
        let (pda, _) = Pubkey::find_program_address(seeds, &program_id);
        pda
    }
    // OK: length-prefixed
    pub fn register_len(name: String, symbol: String, program_id: Pubkey) -> Pubkey {
        let n_len = name.len().to_le_bytes();
        let seeds: &[&[u8]] = &[&n_len, name.as_bytes(), symbol.as_bytes()];
        let (pda, _) = Pubkey::find_program_address(seeds, &program_id);
        pda
    }
}
