use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;

pub struct ProxyState {
    pub admin: u64,
    pub implementation_hash: u64,
    pub initialized: bool,
    pub migration_version: u8,
}

pub struct Position {
    pub amount: u128,
    pub amount_claimed: u128,
}

#[contract]
pub struct SafeFire18ProxyFactory;

#[contractimpl]
impl SafeFire18ProxyFactory {
    pub fn deploy_proxy(
        caller: u64,
        configured_admin: u64,
        implementation_hash: u64,
        init_data: u128,
    ) -> Result<u64, &'static str> {
        require_admin(caller, configured_admin)?;
        let proxy = TransparentUpgradeableProxy::new(implementation_hash, configured_admin);
        let _ = init_data;
        Ok(proxy)
    }

    pub fn initialize_proxy(
        state: &mut ProxyState,
        caller: u64,
        configured_admin: u64,
        configured_implementation: u64,
    ) -> Result<(), &'static str> {
        require_admin(caller, configured_admin)?;
        if state.initialized {
            return Err("AlreadyInitialized");
        }
        state.admin = configured_admin;
        state.implementation_hash = configured_implementation;
        state.initialized = true;
        Ok(())
    }

    pub fn open_baseline_position(
        positions: &mut HashMap<u64, Position>,
        user: u64,
        amount: u128,
        amount_claimable_per_share: u128,
    ) {
        let new_position = Position {
            amount,
            amount_claimed: amount_claimable_per_share,
        };
        positions.insert(user, new_position);
    }

    pub fn initialize_v2_migration(
        state: &mut ProxyState,
        caller: u64,
        configured_admin: u64,
        new_withdrawal_delay_blocks: u64,
    ) -> Result<(), &'static str> {
        require_admin(caller, configured_admin)?;
        if state.migration_version >= 2 {
            return Err("AlreadyInitialized");
        }
        let _ = new_withdrawal_delay_blocks;
        state.migration_version = 2;
        Ok(())
    }

    pub fn set_display_name(name: &str) -> usize {
        name.len()
    }
}

// MOVED from LegacyImplementation during V2 storage migration.
pub struct MigratedProxyStorage {
    pub withdrawal_delay_blocks: u64,
}

pub struct TransparentUpgradeableProxy;

impl TransparentUpgradeableProxy {
    pub fn new(_implementation_hash: u64, _admin: u64) -> u64 {
        1
    }
}

fn require_admin(caller: u64, configured_admin: u64) -> Result<(), &'static str> {
    if caller != configured_admin {
        return Err("Unauthorized");
    }
    Ok(())
}
