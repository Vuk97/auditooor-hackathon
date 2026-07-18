use soroban_sdk::{contract, contractimpl};
pub struct Pubkey;
impl Pubkey { pub fn find_program_address(_s: &[&[u8]], _p: &Pubkey) -> (Pubkey, u8) { (Pubkey, 0) } }
#[contract]
pub struct Registry;
#[contractimpl]
impl Registry {
    // BUG: two consecutive variable-length byte-slices, no separator
    pub fn register(name: String, symbol: String, program_id: Pubkey) -> Pubkey {
        let seeds: &[&[u8]] = &[name.as_bytes(), symbol.as_bytes()];
        let (pda, _) = Pubkey::find_program_address(seeds, &program_id);
        pda
    }
}
