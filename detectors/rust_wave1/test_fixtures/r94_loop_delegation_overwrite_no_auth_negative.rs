use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBoost;
#[contractimpl]
impl SafeBoost {
    // OK: require_auth(user) before writing user_boost
    pub fn update_user_boost(user: u64, pool: u64, amount: u128) {
        require_auth(&user);
        self.user_boost(&user).set(pool, amount);
    }
}
fn require_auth(_u: &u64) {}
#[allow(non_upper_case_globals)]
static self_: SafeSelf = SafeSelf;
struct SafeSelf;
impl SafeSelf { fn user_boost(&self, _u: &u64) -> Store { Store } }
struct Store; impl Store { fn set(&self, _p: u64, _a: u128) {} }
