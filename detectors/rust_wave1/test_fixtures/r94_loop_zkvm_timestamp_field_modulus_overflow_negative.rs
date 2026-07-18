use soroban_sdk::{contract, contractimpl};
type BabyBear = u32;
const STEP_MAX: u32 = 1 << 30;
pub struct VmState { timestamp: BabyBear, step: BabyBear }
#[contract]
pub struct ZkVm;
#[contractimpl]
impl ZkVm {
    // SAFE: range-checks timestamp/step < STEP_MAX before advancing
    pub fn increment_timestamp(state: &mut VmState) {
        let timestamp: BabyBear = state.timestamp;
        assert!(timestamp < STEP_MAX);
        assert!(state.step < STEP_MAX);
        state.timestamp = timestamp + 1;
        state.step = state.step + 1;
    }
}
