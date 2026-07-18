use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    #[deprecated(note = "use new_price instead")]
    pub fn old_price(_env: Env) -> i128 { 0 }

    pub fn caller(env: Env) -> i128 {
        // VULN: calls deprecated fn.
        Self::old_price(env)
    }
}
