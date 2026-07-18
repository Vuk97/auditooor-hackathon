use soroban_sdk::{contract, contractimpl};
pub struct OracleVersion { pub price: u128, pub valid: bool }
#[contract]
pub struct SafePerennial;
#[contractimpl]
impl SafePerennial {
    // OK: timeout → return with valid = false
    pub fn at_version(timed_out: bool, previous_version: OracleVersion) -> OracleVersion {
        if timed_out {
            return OracleVersion { price: previous_version.price, valid: false };
        }
        OracleVersion { price: 0, valid: true }
    }
}
