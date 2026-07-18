use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn swap_exact_tokens(amount_in: u128, path: [u8; 20], deadline: u64) {
        uniswap_router_swap(amount_in, 0, path, deadline);
    }
}

fn uniswap_router_swap(_in: u128, _min_out: u128, _path: [u8; 20], _deadline: u64) {}
