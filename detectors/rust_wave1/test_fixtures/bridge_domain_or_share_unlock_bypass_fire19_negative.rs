use std::collections::{HashMap, HashSet};

type Address = [u8; 20];

pub struct BridgeClient;

impl BridgeClient {
    pub fn send(&self, _to: Address, _amount: u128) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct SafeShareToken {
    balances: HashMap<Address, u128>,
    unlock_times: HashMap<Address, u64>,
    total_supply: u128,
}

impl SafeShareToken {
    pub fn deposit_and_bridge(
        &mut self,
        bridge: &BridgeClient,
        user: Address,
        amount: u128,
        destination: Address,
    ) -> Result<(), &'static str> {
        self.mint(user, amount);
        if !self.check_unlocked(user) {
            return Err("locked");
        }
        self.burn(user, amount)?;
        bridge.send(destination, amount)?;
        Ok(())
    }

    fn mint(&mut self, user: Address, amount: u128) {
        self.balances.insert(user, amount);
        self.unlock_times.insert(user, now());
        self.total_supply += amount;
    }

    fn check_unlocked(&self, user: Address) -> bool {
        now() >= self.unlock_times.get(&user).copied().unwrap_or(0)
    }

    fn burn(&mut self, user: Address, amount: u128) -> Result<(), &'static str> {
        let current = self.balances.get(&user).copied().unwrap_or(0);
        self.balances.insert(user, current - amount);
        self.total_supply -= amount;
        Ok(())
    }
}

pub struct SafeGenericBridgeFacet {
    allowed_targets: HashSet<Address>,
}

impl SafeGenericBridgeFacet {
    pub fn swap_and_start_bridge_tokens_generic(
        &self,
        target: Address,
        call_data: Vec<u8>,
        user: Address,
    ) -> Result<(), &'static str> {
        let _ = user;
        if !self.allowed_targets.contains(&target) {
            return Err("untrusted target");
        }
        self.execute_swap(target, call_data)
    }

    fn execute_swap(&self, _target: Address, _call_data: Vec<u8>) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct SafeLayerZeroEndpoint {
    failed_message_hashes: HashMap<(u16, u64), [u8; 32]>,
    processed: HashSet<(u16, u64)>,
    allowed_chains: HashSet<u16>,
}

impl SafeLayerZeroEndpoint {
    pub fn lz_receive(
        &mut self,
        src_chain_id: u16,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Result<(), &'static str> {
        if !self.allowed_chains.contains(&src_chain_id) {
            return Err("untrusted source chain");
        }
        if self.processed.contains(&(src_chain_id, nonce)) {
            return Err("replay");
        }
        if payload.len() > 4096 {
            return Err("payload too large");
        }
        let result = self.process_message(src_chain_id, nonce, &payload);
        if result.is_err() {
            let payload_hash = hash(&payload);
            self.failed_message_hashes.insert((src_chain_id, nonce), payload_hash);
        }
        self.processed.insert((src_chain_id, nonce));
        result
    }

    fn process_message(
        &self,
        _src_chain_id: u16,
        _nonce: u64,
        _payload: &[u8],
    ) -> Result<(), &'static str> {
        Ok(())
    }
}

fn hash(_payload: &[u8]) -> [u8; 32] {
    [0; 32]
}

fn now() -> u64 {
    0
}
