use soroban_sdk::{contract, contractimpl};
pub struct Proposal { for_votes: u64, against_votes: u64, abstain_votes: u64 }
fn quorum_numerator() -> u64 { 25 }
fn quorum_denominator_const() -> u64 { 100 }
#[contract]
pub struct Governor;
#[contractimpl]
impl Governor {
    // BUG: quorum measured against cast votes sum, not total_supply
    pub fn _quorum_reached(p: Proposal) -> bool {
        let total_cast = p.for_votes + p.against_votes + p.abstain_votes;
        p.for_votes * quorum_denominator_const() >= total_cast * quorum_numerator()
    }
}
