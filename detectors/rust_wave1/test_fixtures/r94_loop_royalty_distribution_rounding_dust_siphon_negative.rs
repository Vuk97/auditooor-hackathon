use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Recipient { who: Address, bps: u64 }
fn load_recipients() -> Vec<Recipient> { Vec::new() }
fn transfer(_to: Address, _amt: u64) {}
#[contract]
pub struct Artifact;
#[contractimpl]
impl Artifact {
    // SAFE: last recipient gets the leftover after integer division
    pub fn distribute_royalties(amount: u64) {
        let recipients = load_recipients();
        let last_idx = recipients.len() - 1;
        let mut remaining = amount;
        for (i, r) in recipients.iter().enumerate() {
            if i == last_idx {
                transfer(r.who, remaining);
            } else {
                let share = amount * r.bps / 10000;
                remaining = remaining - share;
                transfer(r.who, share);
            }
        }
    }
}
