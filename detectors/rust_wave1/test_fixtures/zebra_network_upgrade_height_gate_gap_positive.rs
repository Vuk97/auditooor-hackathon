pub enum NetworkUpgrade {
    Canopy,
    Nu5,
}

pub struct BranchId(u32);
pub struct Transaction;

impl NetworkUpgrade {
    pub fn branch_id(&self) -> Option<BranchId> {
        Some(BranchId(0xc2d6_d0b4))
    }
}

impl Transaction {
    pub fn network_upgrade(&self) -> Option<NetworkUpgrade> {
        Some(NetworkUpgrade::Nu5)
    }
}

pub fn verify_orchard_proof(_proof: &[u8], _branch: BranchId) -> Result<(), ()> {
    Ok(())
}

pub fn validate_orchard_bundle(tx: &Transaction, proof: &[u8]) -> Result<(), ()> {
    let selected_upgrade = tx.network_upgrade().unwrap_or(NetworkUpgrade::Nu5);
    let branch = selected_upgrade.branch_id().ok_or(())?;
    verify_orchard_proof(proof, branch)
}
