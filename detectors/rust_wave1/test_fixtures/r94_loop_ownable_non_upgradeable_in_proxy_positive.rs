// non-upgradeable Ownable in an upgradeable contract
use openzeppelin::access::ownable::Ownable;
use soroban_sdk::{contract, contractimpl};
trait Initializable { fn initialize(&self); }
#[contract]
pub struct Staking;
#[contractimpl]
impl Staking {
    pub fn initialize() {
        // BUG: Ownable (non-upgradeable) is used with Initializable
    }
}
