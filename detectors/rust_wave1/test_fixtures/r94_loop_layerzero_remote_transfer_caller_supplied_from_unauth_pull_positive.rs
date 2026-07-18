use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn transfer_from(_token: Address, _from: Address, _to: Address, _amount: u64) {}
#[contract]
pub struct USDO;
#[contractimpl]
impl USDO {
    // BUG: `from` comes from the caller's parameters, not the attested LZ payload
    pub fn remote_transfer(token: Address, from: Address, to: Address, amount: u64) {
        transfer_from(token, from, to, amount);
    }
}
