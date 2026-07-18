use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];

fn balance_of(_t: Address, _w: Address) -> u128 { 0 }
fn transfer_from(_f: Address, _t: Address, _a: u128) {}
fn _mint(_to: Address, _s: u128) {}
fn non_reentrant() {}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn deposit(user: Address, amount: u128) {
        non_reentrant();
        let token: Address = [0; 20];
        let self_addr: Address = [0; 20];
        let balance_before = balance_of(token, self_addr);
        transfer_from(user, self_addr, amount);
        let balance_after = balance_of(token, self_addr);
        let received = balance_after - balance_before;
        _mint(user, received);
    }
}
