use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Symbol};

#[contract]
pub struct ReplayBook;

#[contractimpl]
impl ReplayBook {
    fn action_digest(
        env: &Env,
        action_tag: Symbol,
        user: Address,
        amount: i128,
        nonce: u64,
    ) -> Bytes {
        let mut payload = Bytes::new();
        payload.append(&env.current_contract_address().serialize());
        payload.append(&action_tag.serialize());
        payload.append(&user.serialize());
        payload.append(&amount.serialize());
        payload.append(&nonce.serialize());
        let _digest = sha256(&payload);
        payload
    }

    pub fn claim_rewards(
        env: Env,
        signer: BytesN<32>,
        sig: BytesN<64>,
        user: Address,
        amount: i128,
        nonce: u64,
    ) {
        let digest = Self::action_digest(
            &env,
            Symbol::new(&env, "claim_rewards"),
            user.clone(),
            amount,
            nonce,
        );
        env.crypto().ed25519_verify(&signer, &digest, &sig);
        let rewards_key = (Symbol::new(&env, "rewards"), user);
        env.storage().persistent().set(&rewards_key, &amount);
    }

    pub fn withdraw_rewards(
        env: Env,
        signer: BytesN<32>,
        sig: BytesN<64>,
        user: Address,
        amount: i128,
        nonce: u64,
    ) {
        let digest = Self::action_digest(
            &env,
            Symbol::new(&env, "withdraw_rewards"),
            user.clone(),
            amount,
            nonce,
        );
        env.crypto().ed25519_verify(&signer, &digest, &sig);
        let withdraw_key = (Symbol::new(&env, "withdraw"), user);
        env.storage().persistent().set(&withdraw_key, &amount);
    }
}

fn sha256(data: &Bytes) -> Bytes {
    data.clone()
}
