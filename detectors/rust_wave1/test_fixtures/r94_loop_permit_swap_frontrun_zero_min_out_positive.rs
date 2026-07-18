use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Router;
#[contractimpl]
impl Router {
    // BUG: permit_sig + caller-controlled amount_out_min, no sig-binding
    pub fn swap_with_permit(amount_in: u128, amount_out_min: u128, permit_sig: [u8; 65]) -> u128 {
        apply_permit(permit_sig);
        let out = do_swap(amount_in);
        if out < amount_out_min { panic!("slippage"); }
        out
    }
}
fn apply_permit(_s: [u8; 65]) {}
fn do_swap(_a: u128) -> u128 { 0 }
