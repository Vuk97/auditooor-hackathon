use soroban_sdk::{contract, contractimpl};

pub struct Market { open_interest: u128, global_skew: i128 }
fn settle_position(_id: u64) {}
fn load_market() -> Market { Market { open_interest: 10000, global_skew: 0 } }
fn save_market(_m: &Market) {}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn liquidate_position(pos_id: u64) {
        let mut m = load_market();
        m.open_interest -= 1000;
        m.global_skew -= 500;
        save_market(&m);
        settle_position(pos_id);
    }
}
