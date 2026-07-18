// OK: uses OwnableUpgradeable (correct for proxy)
use openzeppelin::access::ownable::OwnableUpgradeable;
use soroban_sdk::{contract, contractimpl};
trait Initializable { fn initialize(&self); }
#[contract]
pub struct Staking;
#[contractimpl]
impl Staking {
    pub fn initialize() {
        // using OwnableUpgradeable — consistent with proxy
    }
}
