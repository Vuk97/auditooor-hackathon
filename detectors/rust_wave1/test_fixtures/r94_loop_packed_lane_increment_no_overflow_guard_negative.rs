// NEGATIVE fixture: Same packed-lane struct, but with an explicit
// `< u8::MAX` guard + checked_add branch before the mutation.
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct MarketDataPacked;

#[contractimpl]
impl MarketDataPacked {
    pub fn increment_question_count(lane: u8) -> Result<u8, ()> {
        // Explicit lane-max guard — bails out before overflow.
        if lane < u8::MAX {
            let next = lane.checked_add(1).ok_or(())?;
            let _bits = next & 0xFF;
            Ok(next)
        } else {
            Err(())
        }
    }
}
