use soroban_sdk::{contract, contractimpl};
pub struct OracleVersion { pub price: u128, pub valid: bool }
#[contract]
pub struct Perennial;
#[contractimpl]
impl Perennial {
    // BUG: commit timeout → returns previous version as valid
    pub fn at_version(timed_out: bool, previous_version: OracleVersion) -> OracleVersion {
        if timed_out {
            return previous_version;
        }
        OracleVersion { price: 0, valid: true }
    }
}
