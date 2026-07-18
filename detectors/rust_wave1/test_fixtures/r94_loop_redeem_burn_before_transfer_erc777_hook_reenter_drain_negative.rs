use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];

pub struct Coll {
    addr: Address,
}

impl Coll {
    fn transfer(&self, _to: Address, _a: u128) {}
}

fn _burn(_t: Address, _a: u128) {}
fn non_reentrant() {}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn redeem(user: Address, ag_token: Address, coll_addr: Address, amount: u128) {
        non_reentrant();
        let collateral = Coll { addr: coll_addr };
        _burn(ag_token, amount);
        collateral.transfer(user, amount);
    }
}
