use soroban_sdk::{contract, contractimpl, Address, Env, Vec};

const MAX_RECIPIENTS: u32 = 50;

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn airdrop(_env: Env, recipients: Vec<Address>, amount: i128) -> i128 {
        assert!(recipients.len() <= MAX_RECIPIENTS);
        let mut total: i128 = 0;
        for _r in recipients.iter() {
            total += amount;
        }
        total
    }
}
