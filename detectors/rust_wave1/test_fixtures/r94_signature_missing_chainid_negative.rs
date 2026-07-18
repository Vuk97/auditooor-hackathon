use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: digest includes the ledger's network_id (chain identity) before
    // verifying — cross-chain replay blocked.
    pub fn execute_intent(env: Env, pubkey: BytesN<32>, mut msg: Bytes, sig: BytesN<64>, taker: Address, deadline: u64, amount: i128) {
        if env.ledger().timestamp() > deadline {
            panic!("expired");
        }
        let network_id: BytesN<32> = env.ledger().network_id();
        msg.append(&network_id.into());
        env.crypto().ed25519_verify(&pubkey, &msg, &sig);
        let bal_key = (Symbol::new(&env, "bal"), taker);
        env.storage().persistent().set(&bal_key, &amount);
    }
}
