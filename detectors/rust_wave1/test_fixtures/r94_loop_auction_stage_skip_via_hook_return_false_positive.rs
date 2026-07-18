use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Proposal;
#[contractimpl]
impl Proposal {
    // BUG: settle-hook returns bool; on false we advance to next stage
    pub fn execute(step: u64) -> u64 {
        let ok = _settle_zora_auction(step);
        if !ok {
            list_on_opensea(step);
        }
        step + 1
    }
}
fn _settle_zora_auction(_s: u64) -> bool { true }
fn list_on_opensea(_s: u64) {}
