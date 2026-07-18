use soroban_sdk::{contract, contractimpl};
pub struct Collection { pub key: u128, pub verified: bool }
pub struct NftMetadata { pub collection: Collection }
#[contract]
pub struct SafeStaker;
#[contractimpl]
impl SafeStaker {
    // OK: asserts both collection.key AND collection.verified
    pub fn stake(nft_metadata: NftMetadata, whitelist: u128) {
        require(nft_metadata.collection.key == whitelist);
        require(nft_metadata.collection.verified == true);
        credit_rewards();
    }
}
fn credit_rewards() {}
fn require(_c: bool) {}
