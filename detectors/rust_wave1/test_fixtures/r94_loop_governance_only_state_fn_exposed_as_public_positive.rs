use soroban_sdk::{contract, contractimpl};
fn save_impact(_nft_id: u64, _score: u64) {}
#[contract]
pub struct ServiceNft;
#[contractimpl]
impl ServiceNft {
    // BUG: update_impact is public but no onlyGovernance / onlyOwner guard
    pub fn update_impact(nft_id: u64, score: u64) {
        save_impact(nft_id, score);
    }
}
