use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Fire19Reentrancy;

#[contractimpl]
impl Fire19Reentrancy {
    // BUG: token receive callback can run between the balance snapshot and diff.
    pub fn receive_token_delta(token: Token, amount: u128) -> u128 {
        let balance_before = token_balance(vault_address());
        token_receive(token, amount);
        let actual_received = token_balance(vault_address()) - balance_before;
        record_deposit(actual_received);
        actual_received
    }

    // BUG: hub guard is local; hook can re-enter the direct pool manager path.
    pub fn add_liquidity_with_hook(hook: Hook, pool_key: u64, amount: u128) {
        enter_hub_guard(pool_key);
        hook.before_add_liquidity(pool_key, amount);
        pool_manager.modify_liquidity(pool_key, amount);
        self.reserves += amount;
        exit_hub_guard(pool_key);
    }

    // BUG: collateral leaves before liquidation state is committed.
    pub fn liquidate_position(token: Token, liquidator: Liquidator, borrower: u64, amount: u128) {
        token.transfer(liquidator.addr(), amount);
        liquidator.on_liquidation(borrower, amount);
        self.debts.remove(&borrower);
        mark_liquidated(borrower);
    }
}

pub struct Token;
impl Token {
    pub fn transfer(&self, _to: u64, _amount: u128) {}
}

pub struct Hook;
impl Hook {
    pub fn before_add_liquidity(&self, _pool_key: u64, _amount: u128) {}
}

pub struct Liquidator;
impl Liquidator {
    pub fn addr(&self) -> u64 { 7 }
    pub fn on_liquidation(&self, _borrower: u64, _amount: u128) {}
}

struct PoolManager;
impl PoolManager {
    fn modify_liquidity(&self, _pool_key: u64, _amount: u128) {}
}

#[allow(non_upper_case_globals)]
static pool_manager: PoolManager = PoolManager;

fn token_receive(_token: Token, _amount: u128) {}
fn token_balance(_who: u64) -> u128 { 0 }
fn vault_address() -> u64 { 1 }
fn record_deposit(_actual_received: u128) {}
fn enter_hub_guard(_pool_key: u64) {}
fn exit_hub_guard(_pool_key: u64) {}
fn mark_liquidated(_borrower: u64) {}
