use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];

fn transfer(_to: Address, _amt: u128) {}
fn update_account_rewards(_u: Address) {}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn redeem_shares(user: Address, shares: u128) {
        let collateral_amount: u128 = shares;
        transfer(user, collateral_amount);
        update_account_rewards(user);
    }
}
