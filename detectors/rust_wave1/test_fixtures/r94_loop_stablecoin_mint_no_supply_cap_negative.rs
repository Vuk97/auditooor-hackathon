// Negative fixture for r94_loop_stablecoin_mint_no_supply_cap.
//
// Same Soroban stablecoin shape as the positive fixture, but the mint
// path enforces a max_supply cap with an `assert!` before crediting.
// Detector should NOT fire.
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct SafeStableUSD;

#[contractimpl]
impl SafeStableUSD {
    pub fn mint_stable(env: Env, to: Address, amount: i128) {
        // Auth gate is present.
        let mkey = Symbol::new(&env, "Minter");
        let minter: Address = env.storage().instance().get(&mkey).unwrap();
        minter.require_auth();

        // SUPPLY CAP GUARD: explicit comparison + assert before credit.
        let skey = Symbol::new(&env, "TotalSupply");
        let prev_supply: i128 = env.storage().instance().get(&skey).unwrap_or(0);
        let max_supply: i128 = 1_000_000_000;
        assert!(prev_supply + amount <= max_supply, "supply_cap");

        env.storage().instance().set(&skey, &(prev_supply + amount));

        let bkey = (Symbol::new(&env, "Balance"), to);
        let prev: i128 = env.storage().persistent().get(&bkey).unwrap_or(0);
        env.storage().persistent().set(&bkey, &(prev + amount));
    }
}
