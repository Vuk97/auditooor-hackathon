type Address = [u8; 20];
type Hash32 = [u8; 32];

pub struct Proof {
    pub nodes: Vec<Hash32>,
}

pub struct BridgeVault;

impl BridgeVault {
    pub fn finalize_bridge_proof_release(
        &mut self,
        source_chain: u64,
        destination_chain: u64,
        nonce: u64,
        message_hash: Hash32,
        proof: Proof,
        recipient: Address,
        amount: u128,
    ) -> Result<(), &'static str> {
        let leaf = sha256(&(
            source_chain,
            destination_chain,
            nonce,
            message_hash,
            proof.nodes.len() as u64,
            recipient,
            amount,
        ));
        if !verify_merkle_proof(&proof, leaf) {
            return Err("bad proof");
        }

        self.credit_to(recipient, amount)?;
        Ok(())
    }

    fn credit_to(&mut self, _recipient: Address, _amount: u128) -> Result<(), &'static str> {
        Ok(())
    }
}

fn sha256(_parts: &(u64, u64, u64, Hash32, u64, Address, u128)) -> Hash32 {
    [0u8; 32]
}

fn verify_merkle_proof(_proof: &Proof, _leaf: Hash32) -> bool {
    true
}
