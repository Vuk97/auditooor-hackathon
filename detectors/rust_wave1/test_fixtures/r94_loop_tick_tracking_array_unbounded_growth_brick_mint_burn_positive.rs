use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

fn load_tick_tracking() -> Vec<i32> { Vec::new() }
fn save_tick_tracking(_v: &Vec<i32>) {}

#[contractimpl]
impl X {
    pub fn mint_liquidity(tick_idx: i32) {
        let mut tick_tracking_: Vec<i32> = load_tick_tracking();
        tick_tracking_.push(tick_idx);
        save_tick_tracking(&tick_tracking_);
    }
}
