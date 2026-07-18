use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Vec};

pub struct TokenClient;
impl TokenClient {
    pub fn new(_e: &Env, _a: &Address) -> Self { TokenClient }
    pub fn transfer(&self, _from: &Address, _to: &Address, _a: &i128) {}
}

pub fn verify_proof(_root: &BytesN<32>, _leaf: &BytesN<32>, _proof: &Vec<BytesN<32>>) -> bool { true }

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: verifies the merkle proof and transfers — but no per-leaf
    // claimed flag is written, so the proof can be replayed unbounded.
    pub fn claim(env: Env, token: Address, to: Address, amount: i128, root: BytesN<32>, leaf: BytesN<32>, proof: Vec<BytesN<32>>) {
        if !verify_proof(&root, &leaf, &proof) {
            panic!("bad proof");
        }
        let t = TokenClient::new(&env, &token);
        t.transfer(&env.current_contract_address(), &to, &amount);
    }
}
