use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct PriceAware;
#[contractimpl]
impl PriceAware {
    // BUG: force_cur_block triggers AMM quote; attacker picks block
    pub fn get_current_price(in_amount: u128, force_cur_block: bool) -> u128 {
        if force_cur_block {
            return router.get_amounts_out(in_amount);
        }
        cached_price()
    }
}
fn cached_price() -> u128 { 0 }
struct Router;
impl Router { fn get_amounts_out(&self, _a: u128) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static router: Router = Router;
