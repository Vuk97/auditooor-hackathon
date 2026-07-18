use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeLending;
#[contractimpl]
impl SafeLending {
    // OK: reads live position from nft_position_manager
    pub fn value_of_position(nft_id: u64) -> u128 {
        let pos = nft_position_manager.positions(nft_id);
        let cached = self.position_liquidity(nft_id);
        let _ = cached;
        pos.liquidity * 100
    }
}
struct Pos { liquidity: u128 }
struct Pm;
impl Pm { fn positions(&self, _id: u64) -> Pos { Pos { liquidity: 0 } } }
#[allow(non_upper_case_globals)]
static nft_position_manager: Pm = Pm;
trait PosCached { fn position_liquidity(&self, id: u64) -> u128; }
impl PosCached for SafeLending { fn position_liquidity(&self, _id: u64) -> u128 { 0 } }
