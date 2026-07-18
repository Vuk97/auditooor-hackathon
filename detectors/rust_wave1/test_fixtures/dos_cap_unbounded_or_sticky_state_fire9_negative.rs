use soroban_sdk::{contract, contractimpl, Address, Env, Map, Symbol};

const MAX_PENDING_USERS: u32 = 32;
const REQUEST_FEE: u64 = 10;

#[contract]
pub struct WithdrawalQueue;

#[derive(Clone)]
pub enum QueueError {
    QueueFull,
    AlreadyPending,
}

fn charge_request_fee(_env: &Env, _user: &Address, _fee: u64) -> Result<(), QueueError> {
    Ok(())
}

#[contractimpl]
impl WithdrawalQueue {
    pub fn request_withdrawal(
        env: Env,
        user: Address,
        amount: u64,
    ) -> Result<(), QueueError> {
        user.require_auth();
        charge_request_fee(&env, &user, REQUEST_FEE)?;

        let pending_key = Symbol::new(&env, "pending_withdrawals");
        let mut pending_by_user: Map<Address, u64> = env
            .storage()
            .persistent()
            .get(&pending_key)
            .unwrap_or(Map::new(&env));

        if pending_by_user.contains_key(user.clone()) {
            return Err(QueueError::AlreadyPending);
        }

        if pending_by_user.len() >= MAX_PENDING_USERS {
            return Err(QueueError::QueueFull);
        }

        pending_by_user.set(user, amount);
        env.storage()
            .persistent()
            .set(&pending_key, &pending_by_user);

        Ok(())
    }
}
