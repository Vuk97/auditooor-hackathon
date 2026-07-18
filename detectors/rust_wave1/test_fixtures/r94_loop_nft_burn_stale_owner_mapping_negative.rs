use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeLib;
#[contractimpl]
impl SafeLib {
    // OK: cross-checks against ERC721.owner_of as well
    pub fn burn_short_record(nft_id: u64, caller: u64, sr: ShortRecord) {
        if sr.owner == caller && erc721.owner_of(nft_id) == caller {
            destroy(nft_id);
        }
    }
}
fn destroy(_n: u64) {}
pub struct ShortRecord { pub owner: u64 }
struct Erc721;
impl Erc721 { fn owner_of(&self, _n: u64) -> u64 { 0 } }
#[allow(non_upper_case_globals)]
static erc721: Erc721 = Erc721;
