use std::collections::{HashMap, HashSet};

type Address = [u8; 20];

pub struct BridgeClient;

impl BridgeClient {
    pub fn send(&self, _to: Address, _amount: u128) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct ShareToken {
    balances: HashMap<Address, u128>,
    unlock_times: HashMap<Address, u64>,
    total_supply: u128,
}

impl ShareToken {
    pub fn deposit_and_bridge(
        &mut self,
        bridge: &BridgeClient,
        user: Address,
        amount: u128,
        destination: Address,
    ) -> Result<(), &'static str> {
        self.mint(user, amount);
        bridge.send(destination, amount)?;
        let current = self.balances.get(&user).copied().unwrap_or(0);
        self.balances.insert(user, current - amount);
        self.total_supply -= amount;
        Ok(())
    }

    fn mint(&mut self, user: Address, amount: u128) {
        self.balances.insert(user, amount);
        self.unlock_times.insert(user, now() + 604800);
        self.total_supply += amount;
    }
}

pub struct GenericBridgeFacet;

impl GenericBridgeFacet {
    pub fn swap_and_start_bridge_tokens_generic(
        &self,
        target: Address,
        call_data: Vec<u8>,
        user: Address,
    ) -> Result<(), &'static str> {
        let _ = user;
        self.execute_swap(target, call_data)
    }

    fn execute_swap(&self, _target: Address, _call_data: Vec<u8>) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct LayerZeroEndpoint {
    failed_messages: HashMap<(u16, u64), Vec<u8>>,
    processed: HashSet<(u16, u64)>,
}

impl LayerZeroEndpoint {
    pub fn lz_receive(
        &mut self,
        src_chain_id: u16,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), &'static str> {
        let result = self.process_message(src_chain_id, nonce, &payload);
        if result.is_err() {
            self.failed_messages.insert((src_chain_id, nonce), payload);
        }
        result
    }

    fn process_message(
        &self,
        _src_chain_id: u16,
        _nonce: u64,
        _payload: &[u8],
    ) -> Result<(), &'static str> {
        Err("failed")
    }
}

fn now() -> u64 {
    0
}
