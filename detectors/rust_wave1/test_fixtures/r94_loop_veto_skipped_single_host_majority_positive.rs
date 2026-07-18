use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Party;
#[contractimpl]
impl Party {
    // BUG: uses all_hosts_accept flag set by partial host vote
    pub fn execute(proposal_id: u64) {
        let _ = proposal_id;
        let all_hosts_accept = true;
        if all_hosts_accept {
            skip_veto_delay();
        }
        run_proposal();
    }
}
fn skip_veto_delay() {}
fn run_proposal() {}
