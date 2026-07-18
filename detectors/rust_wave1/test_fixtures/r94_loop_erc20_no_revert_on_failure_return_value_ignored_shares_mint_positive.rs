use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Token;
impl Token {
    fn transfer_from(&self, _from: Address, _to: Address, _amt: u64) -> bool { false }
}
fn load_token() -> Token { Token }
fn _mint(_to: Address, _shares: u64) {}
#[contract]
pub struct LenderGroup;
#[contractimpl]
impl LenderGroup {
    // BUG: ignores transfer_from return value, then mints shares
    pub fn deposit(who: Address, amount: u64) {
        let token = load_token();
        token.transfer_from(who, [0; 20], amount);
        _mint(who, amount);
    }
}
