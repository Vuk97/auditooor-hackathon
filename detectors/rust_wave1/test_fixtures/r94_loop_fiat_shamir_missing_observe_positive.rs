use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Verifier;
#[contractimpl]
impl Verifier {
    // BUG: derives a challenge without observing any protocol values first
    pub fn verify_recursive(mut transcript: Transcript, openings: Vec<u128>) -> bool {
        let alpha = transcript.challenge();
        let beta = transcript.get_challenge();
        alpha != 0 && beta != 0
    }
    // BUG: observes NOTHING before derive
    pub fn recursive_check(mut fs: FiatShamir) -> u64 {
        fs.challenge()
    }
}
pub struct Transcript;
impl Transcript {
    pub fn challenge(&mut self) -> u64 { 0 }
    pub fn get_challenge(&mut self) -> u64 { 0 }
    pub fn observe(&mut self, _v: u128) {}
}
pub struct FiatShamir;
impl FiatShamir {
    pub fn challenge(&mut self) -> u64 { 0 }
    pub fn observe(&mut self, _v: u128) {}
}
