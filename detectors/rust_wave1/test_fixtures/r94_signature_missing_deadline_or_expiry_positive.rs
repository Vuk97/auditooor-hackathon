use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: verifies a signed quote, transfers on it, but never compares
    // a deadline/expiry against ledger timestamp — quote is valid forever.
    pub fn fill_quote(env: Env, pubkey: BytesN<32>, msg: Bytes, sig: BytesN<64>, taker: Address, nonce: u64, amount: i128) {
        env.crypto().ed25519_verify(&pubkey, &msg, &sig);
        let nkey = (Symbol::new(&env, "nonce"), taker.clone());
        env.storage().persistent().set(&nkey, &nonce);
        // ...pay out
        let bal_key = (Symbol::new(&env, "bal"), taker);
        env.storage().persistent().set(&bal_key, &amount);
    }
}
