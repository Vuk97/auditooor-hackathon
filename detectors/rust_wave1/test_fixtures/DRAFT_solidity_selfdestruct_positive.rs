use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct LidoMirror;

#[contractimpl]
impl LidoMirror {
    pub fn sync_balance() -> u128 {
        let lidoBalance = steth_balance_of();
        updateMirror(lidoBalance);
        lidoBalance
    }
}

fn steth_balance_of() -> u128 {
    1_000
}

fn updateMirror(_amount: u128) {}
