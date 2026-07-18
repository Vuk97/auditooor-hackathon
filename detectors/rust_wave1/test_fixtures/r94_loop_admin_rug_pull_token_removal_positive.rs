use soroban_sdk::{contract, contractimpl};
pub struct Folio { pub basket: Vec<u64> }
#[contract]
pub struct Dtf;
#[contractimpl]
impl Dtf {
    // BUG: only_owner removes tokens with no delay/veto
    pub fn remove_token(folio: &mut Folio, token: u64) {
        require(is_owner());
        folio.basket.retain(|t| *t != token);
    }
}
fn is_owner() -> bool { true }
fn require(_: bool) {}
