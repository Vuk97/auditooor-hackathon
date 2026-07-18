use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeQuest;
#[contractimpl]
impl SafeQuest {
    // OK: sets fee_withdrawn = true after transfer
    pub fn withdraw_fee(token: Token, to: u64, amount: u128) {
        token.transfer(to, amount);
        fee_withdrawn_flag().set(true);
        let _fee_withdrawn = true;
    }
}
pub struct Token;
impl Token { pub fn transfer(&self, _to: u64, _amt: u128) {} }
fn fee_withdrawn_flag() -> Flag { Flag }
struct Flag; impl Flag { fn set(&self, _b: bool) {} }
