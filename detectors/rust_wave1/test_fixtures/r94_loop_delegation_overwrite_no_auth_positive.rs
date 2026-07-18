use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Boost;
#[contractimpl]
impl Boost {
    // BUG: overwrites user_boost without require_auth(user)
    pub fn update_user_boost(user: u64, pool: u64, amount: u128) {
        self.user_boost(&user).set(pool, amount);
    }
}
#[allow(non_upper_case_globals)]
static self_: BoostSelf = BoostSelf;
struct BoostSelf;
impl BoostSelf { fn user_boost(&self, _u: &u64) -> Store { Store } }
struct Store; impl Store { fn set(&self, _p: u64, _a: u128) {} }
