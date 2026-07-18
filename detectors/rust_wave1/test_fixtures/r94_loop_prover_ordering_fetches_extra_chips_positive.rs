use soroban_sdk::{contract, contractimpl};
pub struct Chip { id: u32 }
fn eval_constraints(_c: &Chip) -> bool { true }
fn lookup_chip<'a>(_map: &'a std::collections::HashMap<u32, Chip>, _id: u32) -> &'a Chip {
    unimplemented!()
}
#[contract]
pub struct ZkVerifier;
#[contractimpl]
impl ZkVerifier {
    // BUG: uses prover-supplied chip_ordering to fetch chips, skips ones not in ordering
    pub fn verify_shard(
        chip_ordering: Vec<u32>,
        preprocessed: std::collections::HashMap<u32, Chip>,
    ) -> bool {
        for id in chip_ordering.iter() {
            let chip = preprocessed.get(id).unwrap();
            if !eval_constraints(chip) {
                return false;
            }
        }
        true
    }
}
