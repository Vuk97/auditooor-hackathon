use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeYieldToken;
#[contractimpl]
impl SafeYieldToken {
    // OK: checks allowance before burning from owner
    pub fn redeem(owner: u64, amount: u128) -> u128 {
        let caller = env.invoker();
        self._spend_allowance(owner, caller, amount);
        let bal = self.balances(&owner);
        self._burn(owner, amount);
        bal - amount
    }
}
struct Env { }
impl Env { fn invoker(&self) -> u64 { 0 } }
#[allow(non_upper_case_globals)]
static env: Env = Env{};
