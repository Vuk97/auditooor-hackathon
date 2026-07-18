use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct SafeFire19Reentrancy;

#[contractimpl]
impl SafeFire19Reentrancy {
    // OK: reentrancy guard is set before balance-diff amount inference.
    pub fn receive_token_delta_guarded(token: Token, amount: u128) -> u128 {
        enter_reentrancy_guard();
        let balance_before = token_balance(vault_address());
        token_receive(token, amount);
        let actual_received = token_balance(vault_address()) - balance_before;
        record_deposit(actual_received);
        exit_reentrancy_guard();
        actual_received
    }

    // OK: pool-manager guard is scoped to the path the hook could re-enter.
    pub fn add_liquidity_pool_scoped(hook: Hook, pool_key: u64, amount: u128) {
        enter_pool_manager_guard(pool_key);
        self.reserves += amount;
        hook.before_add_liquidity(pool_key, amount);
        pool_manager.modify_liquidity(pool_key, amount);
        exit_pool_manager_guard(pool_key);
    }

    // OK: liquidation state is finalized before the callback surface.
    pub fn liquidate_position_cei(token: Token, liquidator: Liquidator, borrower: u64, amount: u128) {
        enter_reentrancy_guard();
        self.debts.remove(&borrower);
        mark_liquidated(borrower);
        token.transfer(liquidator.addr(), amount);
        liquidator.on_liquidation(borrower, amount);
        exit_reentrancy_guard();
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
fn enter_reentrancy_guard() {}
fn exit_reentrancy_guard() {}
fn enter_pool_manager_guard(_pool_key: u64) {}
fn exit_pool_manager_guard(_pool_key: u64) {}
fn mark_liquidated(_borrower: u64) {}
