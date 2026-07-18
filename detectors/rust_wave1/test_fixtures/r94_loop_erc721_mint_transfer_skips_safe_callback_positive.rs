use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn _mint(_to: Address, _token_id: u64) {}
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: uses plain _mint — onERC721Received is not invoked on contract recipients
    pub fn mint_nft(to: Address, token_id: u64) {
        _mint(to, token_id);
    }
}
