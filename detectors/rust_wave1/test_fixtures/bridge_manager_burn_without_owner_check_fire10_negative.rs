type Address = [u8; 20];

struct BridgeVault;

impl BridgeVault {
    fn release_nft(&mut self, _token_id: u64, _recipient: Address) -> Result<(), ()> {
        Ok(())
    }
}

pub struct JackpotBridgeManager {
    ticket_owners: std::collections::BTreeMap<u64, Address>,
    bridge_custody: std::collections::BTreeSet<u64>,
    bridge_vault: BridgeVault,
}

impl JackpotBridgeManager {
    pub fn bridge_out(
        &mut self,
        caller: Address,
        token_id: u64,
        recipient: Address,
    ) -> Result<(), ()> {
        let owner = self.owner_of(token_id)?;
        if owner != caller {
            return Err(());
        }
        if !self.bridge_custody.contains(&token_id) {
            return Err(());
        }
        self.ticket_owners.remove(&token_id);
        self.bridge_vault.release_nft(token_id, recipient)?;
        Ok(())
    }

    fn owner_of(&self, token_id: u64) -> Result<Address, ()> {
        self.ticket_owners.get(&token_id).copied().ok_or(())
    }
}
