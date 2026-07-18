use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct IERC20 { addr: Address }
impl IERC20 {
    fn transfer_from(&self, _from: Address, _to: Address, _amt: u64) -> bool { true }
}
fn erc20(_a: Address) -> IERC20 { IERC20 { addr: [0; 20] } }
fn safe_transfer_from(_token: Address, _from: Address, _to: Address, _amt: u64) {}
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // SAFE: uses safe_transfer_from (SafeERC20 helper) that handles non-standard returns
    pub fn deposit(token: Address, from: Address, amount: u64) {
        safe_transfer_from(token, from, [0; 20], amount);
    }
}
