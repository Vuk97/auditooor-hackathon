use soroban_sdk::{contract, contractimpl};
pub struct Folio { pub basket: Vec<u64> }
#[contract]
pub struct SafeDtf;
#[contractimpl]
impl SafeDtf {
    // OK: admin + governance delay
    pub fn remove_token(folio: &mut Folio, token: u64) {
        require(is_owner());
        let queued_at = queue_proposal(token);
        require(queued_at + GOVERNANCE_DELAY <= now());
        folio.basket.retain(|t| *t != token);
    }
}
const GOVERNANCE_DELAY: u64 = 86400;
fn queue_proposal(_t: u64) -> u64 { 0 }
fn now() -> u64 { 0 }
fn is_owner() -> bool { true }
fn require(_: bool) {}
