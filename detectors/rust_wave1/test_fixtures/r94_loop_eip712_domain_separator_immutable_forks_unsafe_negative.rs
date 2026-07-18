// OK: uses _buildDomainSeparator at runtime; refreshes on chainid change
const DOMAIN_SEPARATOR: [u8; 32] = build_separator();

use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeSigning;
#[contractimpl]
impl SafeSigning {
    pub fn domain_separator() -> [u8; 32] {
        if block_chainid() != cached_chain_id() {
            return _buildDomainSeparator();
        }
        DOMAIN_SEPARATOR
    }
}
const fn build_separator() -> [u8; 32] { [0u8; 32] }
fn _buildDomainSeparator() -> [u8; 32] { [0u8; 32] }
fn block_chainid() -> u64 { 0 }
fn cached_chain_id() -> u64 { 0 }
