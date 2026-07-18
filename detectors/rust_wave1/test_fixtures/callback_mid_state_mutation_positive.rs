use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: `on_flash_loan` callback writes debt without require_auth or
    // a snapshot read.
    pub fn on_flash_loan(env: Env, user: Address, amount: i128) {
        // no require_auth, no .get() snapshot — straight to a .set()
        env.storage().persistent().set(&Symbol::new(&env, "total_debt"), &amount);
        let _ = user;
    }
}
