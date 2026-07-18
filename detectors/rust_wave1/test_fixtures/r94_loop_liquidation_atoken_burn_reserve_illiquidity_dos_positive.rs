use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct AToken;
impl AToken {
    fn burn(&self, _from: Address, _to: Address, _amount: u64) {}
}
#[contract]
pub struct LiquidationCall;
#[contractimpl]
impl LiquidationCall {
    // BUG: burns aToken unconditionally, reverts when reserve illiquid (DOS)
    pub fn liquidate(borrower: Address, liquidator: Address, amount: u64) {
        let a_token = AToken;
        a_token.burn(borrower, liquidator, amount);
    }
}
