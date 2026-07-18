// BUG: DOMAIN_SEPARATOR cached as immutable at construction, no chainid refresh
const DOMAIN_SEPARATOR: [u8; 32] = build_separator();

use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Signing;
#[contractimpl]
impl Signing {
    pub fn domain_separator() -> [u8; 32] {
        DOMAIN_SEPARATOR
    }
}
const fn build_separator() -> [u8; 32] { [0u8; 32] }
