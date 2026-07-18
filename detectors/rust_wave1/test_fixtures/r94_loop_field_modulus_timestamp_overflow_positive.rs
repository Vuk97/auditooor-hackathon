// ZK-VM context: BabyBear prime field
use soroban_sdk::{contract, contractimpl};
use BabyBear as F;
pub struct BabyBear;
#[contract]
pub struct Vm;
#[contractimpl]
impl Vm {
    // BUG: timestamp counter advanced with no modulus check
    pub fn step(timestamp: u64) -> u64 {
        let next_timestamp = timestamp + 1;
        next_timestamp
    }
    pub fn tick(counter: u64) -> u64 {
        let c = counter + 1;
        c
    }
}
