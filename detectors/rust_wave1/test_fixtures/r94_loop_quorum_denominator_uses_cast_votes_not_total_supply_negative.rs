use soroban_sdk::{contract, contractimpl};
pub struct Proposal { for_votes: u64, against_votes: u64, abstain_votes: u64 }
fn quorum_numerator() -> u64 { 25 }
fn quorum_denominator_const() -> u64 { 100 }
fn total_supply() -> u64 { 1_000_000 }
#[contract]
pub struct Governor;
#[contractimpl]
impl Governor {
    // SAFE: quorum measured against totalSupply()
    pub fn _quorum_reached(p: Proposal) -> bool {
        let supply = total_supply();
        p.for_votes * quorum_denominator_const() >= supply * quorum_numerator()
    }
}
