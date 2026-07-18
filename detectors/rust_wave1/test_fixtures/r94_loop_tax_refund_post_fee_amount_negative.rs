use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeTaxToken;
#[contractimpl]
impl SafeTaxToken {
    // OK: refund uses pre-fee input amount (gross)
    pub fn refund(_user: u64, input_amount: u128) -> u128 {
        let gross_amount = input_amount;
        let refund = gross_amount * 5 / 100;
        refund
    }
}
