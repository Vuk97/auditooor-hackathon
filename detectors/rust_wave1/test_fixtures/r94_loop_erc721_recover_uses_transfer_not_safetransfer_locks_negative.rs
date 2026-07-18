use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct IERC721 { addr: Address }
impl IERC721 {
    fn transfer(&self, _to: Address, _token_id: u64) {}
    fn safe_transfer_from(&self, _from: Address, _to: Address, _token_id: u64) {}
}
#[contract]
pub struct Amo;
#[contractimpl]
impl Amo {
    // SAFE: uses safeTransferFrom so receiver's onERC721Received is invoked
    pub fn recover_erc721(nft: IERC721, from: Address, to: Address, token_id: u64) {
        nft.safe_transfer_from(from, to, token_id);
    }
}
