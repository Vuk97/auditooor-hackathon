use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct AToken;
impl AToken {
    fn burn(&self, _from: Address, _to: Address, _amount: u64) {}
    fn transfer(&self, _from: Address, _to: Address, _amount: u64) {}
}
fn reserve_available_liquidity() -> u64 { 0 }
#[contract]
pub struct LiquidationCall;
#[contractimpl]
impl LiquidationCall {
    pub fn liquidate(borrower: Address, liquidator: Address, amount: u64) {
        let a_token = AToken;
        let liquidity = reserve_available_liquidity();
        let fallback_to_atokens = liquidity < amount;
        if !fallback_to_atokens {
            a_token.burn(borrower, liquidator, amount);
        } else {
            a_token.transfer(borrower, liquidator, amount);
        }
    }
}
