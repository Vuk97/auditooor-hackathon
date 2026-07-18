use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct IERC721 { addr: Address }
impl IERC721 {
    fn transfer(&self, _to: Address, _token_id: u64) {}
}
#[contract]
pub struct Amo;
#[contractimpl]
impl Amo {
    // BUG: uses .transfer() on ERC721 — no such method on OZ ERC721, tokens lock
    pub fn recover_erc721(nft: IERC721, to: Address, token_id: u64) {
        nft.transfer(to, token_id);
    }
}
