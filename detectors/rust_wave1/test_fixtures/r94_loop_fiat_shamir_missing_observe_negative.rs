use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVerifier;
#[contractimpl]
impl SafeVerifier {
    // OK: observes protocol values BEFORE deriving the challenge
    pub fn verify_recursive(mut transcript: Transcript, openings: Vec<u128>) -> bool {
        for o in &openings {
            transcript.observe(*o);
        }
        let alpha = transcript.challenge();
        alpha != 0
    }
    // OK: absorb before challenge
    pub fn recursive_check(mut fs: FiatShamir, vk: u128, commits: Vec<u128>) -> u64 {
        fs.observe(vk);
        for c in &commits { fs.observe(*c); }
        fs.challenge()
    }
}
pub struct Transcript;
impl Transcript {
    pub fn challenge(&mut self) -> u64 { 0 }
    pub fn observe(&mut self, _v: u128) {}
}
pub struct FiatShamir;
impl FiatShamir {
    pub fn challenge(&mut self) -> u64 { 0 }
    pub fn observe(&mut self, _v: u128) {}
}
