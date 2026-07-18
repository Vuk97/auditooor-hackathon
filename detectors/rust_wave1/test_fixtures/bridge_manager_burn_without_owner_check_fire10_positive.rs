type Address = [u8; 20];

struct BridgeVault;

impl BridgeVault {
    fn release_nft(&mut self, _token_id: u64, _recipient: Address) -> Result<(), ()> {
        Ok(())
    }
}

pub struct JackpotBridgeManager {
    ticket_owners: std::collections::BTreeMap<u64, Address>,
    bridge_vault: BridgeVault,
}

impl JackpotBridgeManager {
    pub fn bridge_out(
        &mut self,
        caller: Address,
        token_id: u64,
        recipient: Address,
    ) -> Result<(), ()> {
        self.ticket_owners.remove(&token_id);
        self.bridge_vault.release_nft(token_id, recipient)?;
        self.pay_bridge(caller, token_id)?;
        Ok(())
    }

    fn pay_bridge(&self, _caller: Address, _token_id: u64) -> Result<(), ()> {
        Ok(())
    }
}
