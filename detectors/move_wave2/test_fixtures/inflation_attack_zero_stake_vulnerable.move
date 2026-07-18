// fixture: positive — inflation_attack_zero_stake (VULNERABLE)
// Bug: shares computed via total_shares / total_stake with no zero-stake guard.
module staking::pool {
    struct Pool has key {
        total_stake: u64,
        total_shares: u64,
    }

    public entry fun stake(pool: &mut Pool, amount: u64): u64 {
        // Bug: if total_stake == 0, division by zero or manipulation possible
        let shares_to_mint = amount * pool.total_shares / pool.total_stake;
        pool.total_stake = pool.total_stake + amount;
        pool.total_shares = pool.total_shares + shares_to_mint;
        shares_to_mint
    }
}
