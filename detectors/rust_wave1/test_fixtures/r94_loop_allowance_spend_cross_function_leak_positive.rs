use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct YieldToken;
#[contractimpl]
impl YieldToken {
    // BUG: burns from `owner` without checking allowance from caller
    pub fn redeem(owner: u64, amount: u128) -> u128 {
        let caller = env_invoker();
        let _ = caller;
        let _ = env.invoker();
        let bal = self.balances(&owner);
        self._burn(owner, amount);
        bal - amount
    }
}
fn env_invoker() -> u64 { 0 }
struct Env { }
impl Env { fn invoker(&self) -> u64 { 0 } }
#[allow(non_upper_case_globals)]
static env: Env = Env{};
