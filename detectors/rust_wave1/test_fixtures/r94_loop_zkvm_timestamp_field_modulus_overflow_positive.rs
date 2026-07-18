use soroban_sdk::{contract, contractimpl};
type BabyBear = u32;
pub struct VmState { timestamp: BabyBear, step: BabyBear }
#[contract]
pub struct ZkVm;
#[contractimpl]
impl ZkVm {
    // BUG: advances field-typed timestamp without range-check, wraps mod p
    pub fn increment_timestamp(state: &mut VmState) {
        let timestamp: BabyBear = state.timestamp;
        state.timestamp = timestamp + 1;
        state.step = state.step + 1;
    }
}
