use soroban_sdk::{contract, contractimpl, Address, Env, Vec};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: iterates caller Vec without bounds.
    pub fn airdrop(_env: Env, recipients: Vec<Address>, amount: i128) -> i128 {
        let mut total: i128 = 0;
        for _r in recipients.iter() {
            total += amount;
        }
        total
    }
}
