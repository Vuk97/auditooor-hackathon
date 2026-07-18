use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBridge;
#[contractimpl]
impl SafeBridge {
    // OK: require_auth(owner) — only owner can bridge their NFT
    pub fn bridge_nft(destination: u64, token_id: u64) {
        let owner = owner_of(token_id);
        require_auth(owner);
        nft.transfer_from(owner, destination, token_id);
    }
}
fn owner_of(_id: u64) -> u64 { 0 }
fn require_auth(_o: u64) {}
struct Nft;
impl Nft { fn transfer_from(&self, _f: u64, _t: u64, _i: u64) {} }
#[allow(non_upper_case_globals)]
static nft: Nft = Nft;
