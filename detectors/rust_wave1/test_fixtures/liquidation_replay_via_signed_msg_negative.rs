use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn execute_liquidation(env: Env, pubkey: BytesN<32>, msg: Bytes, sig: BytesN<64>, target: Address, nonce: u64, amount: i128) {
        let nkey = (Symbol::new(&env, "nonce"), target.clone());
        let last: u64 = env.storage().persistent().get(&nkey).unwrap_or(0);
        if nonce <= last { panic!("nonce reuse"); }
        env.crypto().ed25519_verify(&pubkey, &msg, &sig);
        env.storage().persistent().set(&nkey, &nonce);
        let key = (Symbol::new(&env, "collateral"), target);
        env.storage().persistent().set(&key, &amount);
    }
}
