use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];
pub struct Token;
impl Token { fn transfer(&self, _to: Address, _amt: u128) {} }
fn load_usdce() -> Token { Token }

// Sibling adapter — note the name contains `Adapter` and `Collateral`.
#[contract]
pub struct CtfCollateralAdapter;

#[contractimpl]
impl CtfCollateralAdapter {
    // VULN: token motion with no consult of hub `paused()` and no local guard.
    pub fn redeem_positions(recipient: Address, amount: u128) {
        let token = load_usdce();
        token.transfer(recipient, amount);
    }
}
