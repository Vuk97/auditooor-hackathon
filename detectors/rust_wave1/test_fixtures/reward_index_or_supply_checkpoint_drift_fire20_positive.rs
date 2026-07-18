use soroban_sdk::{contract, contractimpl};

type Address = [u8; 20];

pub struct Pool {
    total_supply: u128,
    total_shares: u128,
    withdrawal_queue: Vec<Address>,
}

pub struct WithdrawalBuffer {
    erc20_buffer: u64,
    buffer_cap: u64,
}

fn reward_per_token_stored() -> u128 { 100 }
fn reward_per_token_paid(_user: Address) -> u128 { 40 }
fn balance_of(_user: Address) -> u128 { 10 }
fn total_supply() -> u128 { 50_000_000 }
fn total_cliffs() -> u128 { 1_000 }
fn do_mint(_amount: u128) {}
fn load_pool() -> Pool {
    Pool { total_supply: 1_000, total_shares: 1_000, withdrawal_queue: Vec::new() }
}
fn save_pool(_pool: &Pool) {}
fn transfer_rewards(_user: Address, _amount: u128) {}
fn get_buffer() -> WithdrawalBuffer {
    WithdrawalBuffer { erc20_buffer: 0, buffer_cap: 1_000_000 }
}
fn save_buffer(_buf: &WithdrawalBuffer) {}

#[contract]
pub struct RewardPool;

#[contractimpl]
impl RewardPool {
    pub fn claim(user: Address) -> u128 {
        let stored = reward_per_token_stored();
        let paid = reward_per_token_paid(user);
        balance_of(user) * (stored - paid) / 1_000_000_000
    }

    pub fn mint_rewards(amount: u128) -> u128 {
        let cliff = total_supply() / 100_000;
        if cliff < total_cliffs() {
            let reduction = total_cliffs() - cliff;
            do_mint(amount);
            return amount * reduction / total_cliffs();
        }
        0
    }

    pub fn withdraw(user: Address, shares: u128) {
        let mut pool = load_pool();
        pool.total_shares -= shares;
        pool.withdrawal_queue.push(user);
        let reward_due = shares * reward_per_token_stored() / pool.total_shares;
        save_pool(&pool);
        transfer_rewards(user, reward_due);
    }

    pub fn complete_queued_withdrawal(amount: u64) {
        let mut buf = get_buffer();
        buf.erc20_buffer = buf.erc20_buffer + amount;
        assert!(buf.erc20_buffer <= buf.buffer_cap, "buffer overflow");
        save_buffer(&buf);
    }
}
