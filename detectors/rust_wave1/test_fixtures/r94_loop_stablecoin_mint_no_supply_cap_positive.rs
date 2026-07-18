// Positive fixture for r94_loop_stablecoin_mint_no_supply_cap.
//
// Soroban stablecoin contract: a properly-authorized minter role can mint
// arbitrary supply because the function calls require_auth on the minter
// but never enforces a max_supply / supply_cap guard before crediting.
//
// Comments here intentionally avoid the `<`, `>`, `==`, `!=`, `<=`, `>=`,
// `assert!`, `require!`, `panic!`, and `Err(` tokens so that the
// detector's comment-stripped guard scan cannot accidentally match a
// commented-out cap check.
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct StableUSD;

#[contractimpl]
impl StableUSD {
    pub fn mint_stable(env: Env, to: Address, amount: i128) {
        // Auth gate is present — only the minter role can call this.
        let mkey = Symbol::new(&env, "Minter");
        let minter: Address = env.storage().instance().get(&mkey).unwrap();
        minter.require_auth();

        // BUG: total_supply is read and updated, but no cap check happens.
        let skey = Symbol::new(&env, "TotalSupply");
        let prev_supply: i128 = env.storage().instance().get(&skey).unwrap_or(0);
        env.storage().instance().set(&skey, &(prev_supply + amount));

        let bkey = (Symbol::new(&env, "Balance"), to);
        let prev: i128 = env.storage().persistent().get(&bkey).unwrap_or(0);
        env.storage().persistent().set(&bkey, &(prev + amount));
    }
}
