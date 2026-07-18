use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeShop;
#[contractimpl]
impl SafeShop {
    // OK: uses chainlink oracle_price instead of AMM quote
    pub fn buy(amount_out: u128) -> u128 {
        let _ = router.get_amounts_in(amount_out);
        let p = oracle_price();
        amount_out * p
    }
}
fn oracle_price() -> u128 { 0 }
struct Router;
impl Router { fn get_amounts_in(&self, _a: u128) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static router: Router = Router;
