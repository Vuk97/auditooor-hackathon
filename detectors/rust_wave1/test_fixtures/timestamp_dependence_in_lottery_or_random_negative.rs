use soroban_sdk::{contract, contractimpl, BytesN, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn pick_winner(_env: Env, vrf_output: BytesN<32>, n_players: u64) -> u64 {
        // commit-reveal via vrf
        let bytes = vrf_output.to_array();
        let lead = u64::from_be_bytes([bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7]]);
        lead % n_players
    }
}
