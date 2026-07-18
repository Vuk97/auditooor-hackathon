use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeWrapper;
#[contractimpl]
impl SafeWrapper {
    // OK: subtracts deposit_fee before passing to underlying.preview
    pub fn deposit(assets: u128) -> u128 {
        let deposit_fee = assets * 10 / 10_000;
        let net_of_fee = assets - deposit_fee;
        let shares = underlying.preview_deposit(net_of_fee);
        shares
    }
}
struct Underlying;
impl Underlying { fn preview_deposit(&self, _a: u128) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static underlying: Underlying = Underlying;
