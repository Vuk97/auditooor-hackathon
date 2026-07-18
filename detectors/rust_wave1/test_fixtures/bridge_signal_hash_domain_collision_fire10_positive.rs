use std::collections::HashSet;

type Address = [u8; 20];
type Hash32 = [u8; 32];

pub struct BridgeEscrow {
    accepted_signals: HashSet<Hash32>,
    vault: Vault,
}

pub struct Vault;

impl Vault {
    pub fn release(&mut self, _receiver: Address, _amount: u128) -> Result<(), &'static str> {
        Ok(())
    }
}

impl BridgeEscrow {
    pub fn release_signal(
        &mut self,
        source_chain: u64,
        route_id: u32,
        bridge_address: Address,
        receiver: Address,
        entrypoint: u32,
        token_id: u64,
        amount: u128,
    ) -> Result<(), &'static str> {
        let _ = source_chain;
        let _ = route_id;
        let _ = bridge_address;
        let _ = entrypoint;

        let signal_hash = sha256(&(token_id, amount));
        if !self.accepted_signals.contains(&signal_hash) {
            return Err("signal not accepted");
        }

        self.accepted_signals.remove(&signal_hash);
        self.vault.release(receiver, amount)?;
        Ok(())
    }
}

fn sha256(_parts: &(u64, u128)) -> Hash32 {
    [0u8; 32]
}
