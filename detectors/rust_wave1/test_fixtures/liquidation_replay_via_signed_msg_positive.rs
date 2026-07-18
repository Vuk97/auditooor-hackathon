use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: verifies sig, executes, but doesn't record the signature as used.
    pub fn execute_liquidation(env: Env, pubkey: BytesN<32>, msg: Bytes, sig: BytesN<64>, target: Address, amount: i128) {
        env.crypto().ed25519_verify(&pubkey, &msg, &sig);
        let key = (Symbol::new(&env, "collateral"), target);
        env.storage().persistent().set(&key, &amount);
    }
}
