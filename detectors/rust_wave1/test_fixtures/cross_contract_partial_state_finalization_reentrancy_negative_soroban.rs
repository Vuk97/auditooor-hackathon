use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec, Val, vec};

#[contract]
pub struct BridgeVault;

#[contractimpl]
impl BridgeVault {
    pub fn queue_withdrawal(env: Env, user: Address, amount: i128) {
        user.require_auth();

        let mut state = PendingState::load(&env, &user);
        state.pending_amount = amount;
        state.pending_nonce = state.pending_nonce + 1;
        state.pending_total = state.pending_total + amount;
        state.pending_processed = true;
        state.store(&env, &user);

        let token: Address = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, "TOKEN"))
            .unwrap();
        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "transfer"),
            vec![&env, user.into_val(&env), amount.into_val(&env)],
        );
    }
}

struct PendingState {
    pending_amount: i128,
    pending_nonce: u32,
    pending_total: i128,
    pending_processed: bool,
}

impl PendingState {
    fn load(_env: &Env, _user: &Address) -> Self {
        Self {
            pending_amount: 0,
            pending_nonce: 0,
            pending_total: 0,
            pending_processed: false,
        }
    }

    fn store(&self, _env: &Env, _user: &Address) {
        let _ = self.pending_total;
    }
}
