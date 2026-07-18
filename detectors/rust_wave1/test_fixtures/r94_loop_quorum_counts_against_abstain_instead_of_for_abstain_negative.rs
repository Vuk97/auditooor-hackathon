use soroban_sdk::{contract, contractimpl};
pub struct Proposal { for_votes: u64, against_votes: u64, abstain_votes: u64 }
fn quorum_threshold() -> u64 { 100_000 }
#[contract]
pub struct Governor;
#[contractimpl]
impl Governor {
    // SAFE: quorum numerator uses for_votes + abstain_votes (OZ Governor semantics)
    pub fn _quorum_reached(p: Proposal) -> bool {
        let numerator = p.for_votes + p.abstain_votes;
        numerator >= quorum_threshold()
    }
}
