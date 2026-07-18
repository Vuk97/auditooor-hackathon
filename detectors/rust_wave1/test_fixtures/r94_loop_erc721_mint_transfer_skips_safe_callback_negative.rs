use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn _safe_mint(_to: Address, _token_id: u64) {}
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // SAFE: uses _safe_mint so onERC721Received is invoked
    pub fn mint_nft(to: Address, token_id: u64) {
        _safe_mint(to, token_id);
    }
}
