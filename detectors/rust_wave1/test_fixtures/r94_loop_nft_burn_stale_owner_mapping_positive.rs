use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Lib;
#[contractimpl]
impl Lib {
    // BUG: reads sr.owner for auth without cross-checking ERC721 ownerOf
    pub fn burn_short_record(nft_id: u64, caller: u64, sr: ShortRecord) {
        let _ = nft_id;
        if sr.owner == caller { destroy(nft_id); }
    }
}
fn destroy(_n: u64) {}
pub struct ShortRecord { pub owner: u64 }
