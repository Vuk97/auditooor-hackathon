// ZK-VM context: BabyBear modulus-checked
use soroban_sdk::{contract, contractimpl};
use BabyBear as F;
pub struct BabyBear;
pub const MODULUS: u64 = 0x78000001;
#[contract]
pub struct SafeVm;
#[contractimpl]
impl SafeVm {
    // OK: asserts counter stays below MODULUS
    pub fn step(timestamp: u64) -> u64 {
        let next_timestamp = timestamp + 1;
        assert!(next_timestamp < MODULUS);
        next_timestamp
    }
    // OK: uses to_canonical / wrap helper
    pub fn tick(counter: u64) -> u64 {
        let c = counter + 1;
        to_canonical(c)
    }
}
fn to_canonical(x: u64) -> u64 { x % MODULUS }
