use soroban_sdk::{contract, contractimpl};
pub struct Proposal { for_votes: u64, against_votes: u64, abstain_votes: u64 }
fn quorum_threshold() -> u64 { 100_000 }
#[contract]
pub struct Governor;
#[contractimpl]
impl Governor {
    // BUG: quorum numerator sums against + abstain, inverting the intended meaning
    pub fn _quorum_reached(p: Proposal) -> bool {
        let numerator = p.against_votes + p.abstain_votes;
        numerator >= quorum_threshold()
    }
}
