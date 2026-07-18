type Address = [u8; 20];
type Hash32 = [u8; 32];

pub struct BridgeProof {
    pub nodes: Vec<Hash32>,
}

pub struct Vault;

impl Vault {
    pub fn release(
        &mut self,
        _account: Address,
        _payout: u128,
    ) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct ProofBridge {
    pub vault: Vault,
}

impl ProofBridge {
    pub fn claim_bridge_proof_release(
        &mut self,
        proof: BridgeProof,
        message_hash: Hash32,
        account: Address,
        payout: u128,
    ) -> Result<(), &'static str> {
        let leaf_hash = sha256(&(
            message_hash,
            proof.nodes.len() as u64,
            account,
            payout,
        ));
        if !verify_merkle_proof(&proof, leaf_hash) {
            return Err("bad proof");
        }

        self.vault.release(account, payout)?;
        Ok(())
    }
}

fn sha256(_parts: &(Hash32, u64, Address, u128)) -> Hash32 {
    [0u8; 32]
}

fn verify_merkle_proof(_proof: &BridgeProof, _leaf_hash: Hash32) -> bool {
    true
}
