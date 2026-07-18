use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Lending;
#[contractimpl]
impl Lending {
    // BUG: reads cached position_liquidity, not live pool state
    pub fn value_of_position(nft_id: u64) -> u128 {
        let liq = self.position_liquidity(nft_id);
        liq * 100
    }
}
fn _unused() {}
#[allow(non_upper_case_globals)]
static self_: LendingRef = LendingRef;
struct LendingRef;
impl LendingRef { fn position_liquidity(&self, _i: u64) -> u128 { 0 } }
// Provide trait impl accessible as `self.position_liquidity`
trait Pos { fn position_liquidity(&self, id: u64) -> u128; }
impl Pos for Lending { fn position_liquidity(&self, _id: u64) -> u128 { 0 } }
