use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Mining;
#[contractimpl]
impl Mining {
    // BUG: pushes to tick_tracking array without cap
    pub fn cross_tick(tick: i32) {
        tick_tracking.push(tick);
    }
}
struct TickTracking;
impl TickTracking { fn push(&self, _t: i32) {} }
#[allow(non_upper_case_globals)]
static tick_tracking: TickTracking = TickTracking;
