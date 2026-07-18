use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn save_impact(_nft_id: u64, _score: u64) {}
fn require_auth(_a: &Address) {}
#[contract]
pub struct ServiceNft;
#[contractimpl]
impl ServiceNft {
    // SAFE: require_auth on governance address before state mutation
    pub fn update_impact(governance: Address, nft_id: u64, score: u64) {
        require_auth(&governance);
        save_impact(nft_id, score);
    }
}
