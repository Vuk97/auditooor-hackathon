use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Recipient { who: Address, bps: u64 }
fn load_recipients() -> Vec<Recipient> { Vec::new() }
fn transfer(_to: Address, _amt: u64) {}
#[contract]
pub struct Artifact;
#[contractimpl]
impl Artifact {
    // BUG: per-recipient integer division; truncation residual not routed
    pub fn distribute_royalties(amount: u64) {
        let recipients = load_recipients();
        for r in recipients.iter() {
            let share = amount * r.bps / 10000;
            transfer(r.who, share);
        }
    }
}
