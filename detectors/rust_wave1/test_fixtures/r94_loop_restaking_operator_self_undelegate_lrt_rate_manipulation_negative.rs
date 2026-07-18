use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Env { pub msg_sender: Address }
fn remove_delegation(_staker: Address) {}
fn pay_out_lrt(_staker: Address) {}
fn is_operator(_a: Address) -> bool { false }
#[contract]
pub struct DelegationManager;
#[contractimpl]
impl DelegationManager {
    // SAFE: rejects when caller IS the operator
    pub fn undelegate(env: Env, staker: Address) {
        let caller = env.msg_sender;
        assert!(!is_operator(caller), "operator cannot self-undelegate");
        remove_delegation(staker);
        pay_out_lrt(caller);
    }
}
