// POSITIVE: try_serialize() called as bare statement (result unused)
use anchor_lang::prelude::*;
use anchor_lang::AnchorSerialize;

fn serialize_config(config: &Config, buf: &mut Vec<u8>) {
    // BAD: bare call, return value discarded, no ? propagation
    config.try_serialize(buf);
    // Program continues with potentially empty/stale buf
}

#[account]
pub struct Config {
    pub fee_rate: u64,
    pub enabled: bool,
    pub reserved: [u8; 32],
}

pub fn process(config: &Config) -> Vec<u8> {
    let mut buf = Vec::new();
    serialize_config(config, &mut buf);
    buf
}
