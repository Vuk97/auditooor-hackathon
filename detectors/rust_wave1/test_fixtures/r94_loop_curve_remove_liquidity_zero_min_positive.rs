use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Controller;
#[contractimpl]
impl Controller {
    // BUG: filters tokens by min_amounts[i] > 0 — drops zero-min tokens Curve returns anyway
    pub fn can_remove_liquidity(underlying: Vec<u64>, min_amounts: Vec<u128>) -> Vec<u64> {
        let mut tokens_in = Vec::new();
        let curve_returns_all = true;
        for (i, tok) in underlying.iter().enumerate() {
            if min_amounts[i] > 0 {
                tokens_in.push(*tok);
            }
        }
        let _remove_liquidity = curve_returns_all;
        tokens_in
    }
}
