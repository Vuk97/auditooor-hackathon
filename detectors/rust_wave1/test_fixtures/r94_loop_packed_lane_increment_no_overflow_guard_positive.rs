// POSITIVE fixture: Soroban-style MarketDataPacked struct increments
// a packed u8 question-count lane inside a u256 slot via shift-assign
// with no `< u8::MAX` / MAX_LANE guard. 256th call silently carries
// into the next packed byte (or panics under Soroban arithmetic).
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct MarketDataPacked;

#[contractimpl]
impl MarketDataPacked {
    // Packed-lane indicator: INCREMENT is a shifted literal; fn
    // applies shift-assign and mask ops to a packed slot. No
    // lane-max guard. Function name matches /^increment/.
    pub fn increment_question_count(data: u128) -> u128 {
        let increment: u128 = 0x01 << 248;
        let mut slot_val: u128 = data;
        slot_val <<= 1;
        slot_val |= 0x01;
        slot_val & 0xFF;
        slot_val + increment
    }
}
