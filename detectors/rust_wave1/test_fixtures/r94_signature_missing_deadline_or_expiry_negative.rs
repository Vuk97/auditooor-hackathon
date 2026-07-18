use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: explicit deadline compared against ledger timestamp before the
    // verify + payout — quote expires.
    pub fn fill_quote(env: Env, pubkey: BytesN<32>, msg: Bytes, sig: BytesN<64>, taker: Address, deadline: u64, amount: i128) {
        if env.ledger().timestamp() > deadline {
            panic!("quote expired");
        }
        env.crypto().ed25519_verify(&pubkey, &msg, &sig);
        let bal_key = (Symbol::new(&env, "bal"), taker);
        env.storage().persistent().set(&bal_key, &amount);
    }
}
