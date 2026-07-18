use std::collections::HashMap;
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct GoodConfig;

#[contractimpl]
impl GoodConfig {
    pub fn set_config(env: Env, caller: Address, value: i128) {
        caller.require_auth();
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "admin_config"), &value);
    }
}

#[derive(Debug, PartialEq)]
pub enum BridgeError {
    UnauthorizedEndpoint,
    InvalidSender,
    MessageAlreadyProcessed,
}

pub struct CrossDomainAdminSafe {
    endpoint: [u8; 32],
    owner: [u8; 32],
    processed_nonces: HashMap<(u64, u64), bool>,
    paused: bool,
    config_version: u64,
}

impl CrossDomainAdminSafe {
    pub fn _receive_message(
        &mut self,
        caller: [u8; 32],
        src_chain_id: u64,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), BridgeError> {
        if caller != self.endpoint_address() {
            return Err(BridgeError::UnauthorizedEndpoint);
        }
        let nonce_key = (src_chain_id, nonce);
        if self.processed_nonces.get(&nonce_key).copied().unwrap_or(false) {
            return Err(BridgeError::MessageAlreadyProcessed);
        }
        self.processed_nonces.insert(nonce_key, true);

        let action = self.decode_payload(&payload)?;
        self.execute_admin_action(src_chain_id, nonce, action)
    }

    pub fn retry_failed_message(
        &mut self,
        caller: [u8; 32],
        src_chain_id: u64,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), BridgeError> {
        if caller != self.endpoint_address() {
            return Err(BridgeError::UnauthorizedEndpoint);
        }
        self._receive_message(caller, src_chain_id, nonce, payload)
    }

    pub fn set_config(&mut self, caller: [u8; 32], value: u64) -> Result<(), BridgeError> {
        if caller != self.owner {
            return Err(BridgeError::UnauthorizedEndpoint);
        }
        self.config_version = value;
        Ok(())
    }

    fn endpoint_address(&self) -> [u8; 32] {
        self.endpoint
    }

    fn decode_payload(&self, payload: &[u8]) -> Result<u8, BridgeError> {
        payload.first().copied().ok_or(BridgeError::InvalidSender)
    }

    fn execute_admin_action(
        &mut self,
        _src_chain_id: u64,
        _nonce: u64,
        action: u8,
    ) -> Result<(), BridgeError> {
        match action {
            1 => {
                self.paused = true;
                Ok(())
            }
            2 => {
                self.config_version += 1;
                Ok(())
            }
            _ => Err(BridgeError::InvalidSender),
        }
    }
}
