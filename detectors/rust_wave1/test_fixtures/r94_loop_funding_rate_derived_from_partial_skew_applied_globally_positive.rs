use soroban_sdk::{contract, contractimpl};

pub struct Maker { skew: i128 }
pub struct Position { accumulated_funding: i128 }

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn compute_funding_rate(oracle_maker: &Maker, all_positions: &mut Vec<Position>) {
        let rate = oracle_maker.skew * 100 / 1_000_000;
        for pos in all_positions.iter_mut() {
            pos.accumulated_funding += rate;
        }
    }
}
