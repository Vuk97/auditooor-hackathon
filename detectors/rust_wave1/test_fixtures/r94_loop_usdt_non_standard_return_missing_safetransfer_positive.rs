use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct IERC20 { addr: Address }
impl IERC20 {
    fn transfer_from(&self, _from: Address, _to: Address, _amt: u64) -> bool { true }
}
fn erc20(_a: Address) -> IERC20 { IERC20 { addr: [0; 20] } }
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: raw IERC20.transfer_from (no SafeERC20); USDT returns void, reverts
    pub fn deposit(token: Address, from: Address, amount: u64) {
        let token_handle = erc20(token);
        let _result = token_handle.transfer_from(from, [0; 20], amount);
    }
}
