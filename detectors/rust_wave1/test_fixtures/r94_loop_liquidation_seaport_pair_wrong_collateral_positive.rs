use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct ClearingHouse;
#[contractimpl]
impl ClearingHouse {
    // BUG: Seaport pair uses fake_nft / clearing_house_nft in consideration
    pub fn liquidate(collateral_id: u64, settlement_token: u64) {
        let _offer = OfferItem { item_type: 2, token: collateral_id };
        let consideration = ConsiderationItem { token: settlement_token, clearing_house_nft: 42 };
        let _ = consideration;
    }
}
pub struct OfferItem { pub item_type: u8, pub token: u64 }
pub struct ConsiderationItem { pub token: u64, pub clearing_house_nft: u64 }
