use soroban_sdk::{contract, contractimpl};
pub struct Collection { pub key: u128, pub verified: bool }
pub struct NftMetadata { pub collection: Collection }
#[contract]
pub struct Staker;
#[contractimpl]
impl Staker {
    // BUG: only checks collection.key, ignores verified
    pub fn stake(nft_metadata: NftMetadata, whitelist: u128) {
        if nft_metadata.collection.key == whitelist {
            credit_rewards();
        }
    }
}
fn credit_rewards() {}
