use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Symbol, Vec};

pub struct TokenClient;
impl TokenClient {
    pub fn new(_e: &Env, _a: &Address) -> Self { TokenClient }
    pub fn transfer(&self, _from: &Address, _to: &Address, _a: &i128) {}
}

pub fn verify_proof(_root: &BytesN<32>, _leaf: &BytesN<32>, _proof: &Vec<BytesN<32>>) -> bool { true }

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: per-leaf `claimed` flag is checked and written before payout,
    // blocking replays.
    pub fn claim(env: Env, token: Address, to: Address, amount: i128, root: BytesN<32>, leaf: BytesN<32>, proof: Vec<BytesN<32>>) {
        let ckey = (Symbol::new(&env, "claimed"), leaf.clone());
        if env.storage().persistent().has(&ckey) {
            panic!("already claimed");
        }
        if !verify_proof(&root, &leaf, &proof) {
            panic!("bad proof");
        }
        env.storage().persistent().set(&ckey, &true);
        let t = TokenClient::new(&env, &token);
        t.transfer(&env.current_contract_address(), &to, &amount);
    }
}
