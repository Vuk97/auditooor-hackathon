use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: picks winner from timestamp.
    pub fn pick_winner(env: Env, n_players: u64) -> u64 {
        env.ledger().timestamp() % n_players
    }
}
