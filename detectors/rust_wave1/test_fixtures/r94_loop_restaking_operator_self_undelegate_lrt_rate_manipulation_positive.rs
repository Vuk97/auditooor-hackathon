use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Env { pub msg_sender: Address }
fn remove_delegation(_staker: Address) {}
fn pay_out_lrt(_staker: Address) {}
#[contract]
pub struct DelegationManager;
#[contractimpl]
impl DelegationManager {
    // BUG: undelegate has no guard — operator can undelegate themselves
    pub fn undelegate(env: Env, staker: Address) {
        let caller = env.msg_sender;
        remove_delegation(staker);
        pay_out_lrt(caller);
    }
}
