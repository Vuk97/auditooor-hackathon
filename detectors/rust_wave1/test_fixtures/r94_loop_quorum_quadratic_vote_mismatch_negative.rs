// OK: quadratic vote + quadratic quorum denominator (consistent)
use openzeppelin::governance::GovernorVotesQuorumFraction;
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct SafeGovernor;
#[contractimpl]
impl SafeGovernor {
    pub fn cast_vote(amount: u128) -> u128 {
        sqrt(amount)
    }

    pub fn quadratic_quorum() -> u128 {
        sqrt_weighted_quorum() / 100
    }
}
fn sqrt(_a: u128) -> u128 { 0 }
fn sqrt_weighted_quorum() -> u128 { 0 }
