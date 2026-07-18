use soroban_sdk::{contract, contractimpl};

pub struct Vesting { total_amount: u128, release_rate: u128, steps: u32 }
fn save_vesting(_v: &Vesting) {}
fn compute_residual_steps(_v: &Vesting) -> u32 { 10 }
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn transfer_vesting(mut grantor: Vesting, transfer_amount: u128) {
        grantor.total_amount = grantor.total_amount - transfer_amount;
        let residual_steps = compute_residual_steps(&grantor);
        grantor.steps = residual_steps;
        grantor.release_rate = grantor.total_amount / residual_steps as u128;
        save_vesting(&grantor);
    }
}
