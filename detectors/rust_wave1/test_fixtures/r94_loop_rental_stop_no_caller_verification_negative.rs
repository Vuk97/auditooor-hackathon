use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeRental;
#[contractimpl]
impl SafeRental {
    // OK: verifies caller == renter || caller == lender before stopping
    pub fn stop_rental(rental_id: u64, nft_id: u64, to: u64, caller: u64, renter: u64, lender: u64) {
        let _ = rental_id;
        require(caller == renter || caller == lender);
        nft.transfer_from(0, to, nft_id);
    }
}
fn require(_c: bool) {}
struct Nft;
impl Nft { fn transfer_from(&self, _f: u64, _t: u64, _i: u64) {} }
#[allow(non_upper_case_globals)]
static nft: Nft = Nft;
