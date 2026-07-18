use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];
pub struct Token;
impl Token { fn transfer(&self, _to: Address, _amt: u128) {} }
fn load_usdce() -> Token { Token }
fn is_paused() -> bool { false }

#[contract]
pub struct CtfCollateralAdapter;

#[contractimpl]
impl CtfCollateralAdapter {
    pub fn redeem_positions(recipient: Address, amount: u128) {
        assert!(!is_paused(), "PAUSED");
        let token = load_usdce();
        token.transfer(recipient, amount);
    }
}
