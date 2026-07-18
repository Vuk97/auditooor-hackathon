use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: verifies the signed intent + pays out, but digest does not
    // include any network/chain identifier — signature forged on a sister
    // deployment (or testnet) can be replayed here.
    pub fn execute_intent(env: Env, pubkey: BytesN<32>, msg: Bytes, sig: BytesN<64>, taker: Address, deadline: u64, amount: i128) {
        if env.ledger().timestamp() > deadline {
            panic!("expired");
        }
        env.crypto().ed25519_verify(&pubkey, &msg, &sig);
        let bal_key = (Symbol::new(&env, "bal"), taker);
        env.storage().persistent().set(&bal_key, &amount);
    }
}
