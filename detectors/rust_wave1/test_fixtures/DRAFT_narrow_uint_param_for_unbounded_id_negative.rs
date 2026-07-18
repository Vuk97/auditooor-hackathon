use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct FighterFarm;

#[contractimpl]
impl FighterFarm {
    pub fn mint_fighter(state: &mut FarmState, owner: Address) -> u64 {
        let id = state.next_id;
        state.next_id = state.next_id.checked_add(1).unwrap();
        mint(owner, id);
        id
    }

    pub fn reroll_fighter(state: &mut FarmState, fighter_id: u64, seed: u64) {
        // OK: entrypoint accepts the same width as the mint counter.
        let id = fighter_id as usize;
        state.reroll(id, seed);
    }
}

pub struct FarmState {
    pub next_id: u64,
}

impl FarmState {
    pub fn reroll(&mut self, _id: usize, _seed: u64) {}
}

pub struct Address;

fn mint(_owner: Address, _id: u64) {}
