use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Rental;
#[contractimpl]
impl Rental {
    // BUG: no caller verification — anyone can stop_rental
    pub fn stop_rental(rental_id: u64, nft_id: u64, to: u64) {
        let _ = rental_id;
        nft.transfer_from(0, to, nft_id);
    }
}
struct Nft;
impl Nft { fn transfer_from(&self, _f: u64, _t: u64, _i: u64) {} }
#[allow(non_upper_case_globals)]
static nft: Nft = Nft;
