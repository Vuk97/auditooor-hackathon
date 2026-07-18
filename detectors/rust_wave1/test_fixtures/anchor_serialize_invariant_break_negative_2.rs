// NEGATIVE: try_to_vec() result checked with match — safe
use anchor_lang::prelude::*;
use borsh::BorshSerialize;

fn safe_serialize(data: &MyData) -> Option<Vec<u8>> {
    match data.try_to_vec() {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            msg!("Serialization failed: {}", e);
            None
        }
    }
}

#[account]
#[derive(BorshSerialize)]
pub struct MyData {
    pub counter: u64,
    pub name: String,
}
