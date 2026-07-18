pub struct Network;
pub struct Height(u32);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NetworkUpgrade {
    Canopy,
    Nu5,
}

pub struct BranchId(u32);
pub struct Transaction;

impl NetworkUpgrade {
    pub fn current(_network: &Network, _height: Height) -> NetworkUpgrade {
        NetworkUpgrade::Nu5
    }

    pub fn branch_id(&self) -> Option<BranchId> {
        Some(BranchId(0xc2d6_d0b4))
    }
}

impl BranchId {
    pub fn current(network: &Network, height: Height) -> Option<BranchId> {
        NetworkUpgrade::current(network, height).branch_id()
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

pub fn validate_orchard_bundle(
    network: &Network,
    height: Height,
    tx: &Transaction,
    proof: &[u8],
) -> Result<(), ()> {
    let expected_upgrade = NetworkUpgrade::current(network, height);
    if tx.network_upgrade() != Some(expected_upgrade) {
        return Err(());
    }

    let branch = BranchId::current(network, height).ok_or(())?;
    verify_orchard_proof(proof, branch)
}
