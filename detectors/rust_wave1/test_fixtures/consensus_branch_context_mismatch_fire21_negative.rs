pub struct Network;

#[derive(Clone, Copy)]
pub struct Height(pub u32);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NetworkUpgrade {
    Canopy,
    Nu5,
}

#[derive(Clone, Copy)]
pub struct BranchId(pub u32);

pub struct Transaction {
    pub height: Height,
    pub network: Network,
    pub branch_id: BranchId,
}

pub struct Validator;

impl BranchId {
    pub fn current(_network: &Network, _height: Height) -> BranchId {
        BranchId(0xc2d6_d0b4)
    }
}

impl NetworkUpgrade {
    pub fn current(_network: &Network, _height: Height) -> NetworkUpgrade {
        NetworkUpgrade::Nu5
    }
}

impl Transaction {
    pub fn network_upgrade(&self) -> Option<NetworkUpgrade> {
        Some(NetworkUpgrade::Nu5)
    }
}

pub fn verify_sighash(_tx: &Transaction, _branch: BranchId) -> Result<(), ()> {
    Ok(())
}

pub fn verify_orchard_proof(_tx: &Transaction, _upgrade: NetworkUpgrade) -> Result<(), ()> {
    Ok(())
}

impl Validator {
    pub fn validate_transaction_with_object_context(tx: &Transaction) -> Result<(), ()> {
        let branch = BranchId::current(&tx.network, tx.height);
        verify_sighash(tx, branch)
    }

    pub fn validate_orchard_bundle_with_upgrade_guard(tx: &Transaction) -> Result<(), ()> {
        let expected_upgrade = NetworkUpgrade::current(&tx.network, tx.height);
        if tx.network_upgrade() != Some(expected_upgrade) {
            return Err(());
        }

        verify_orchard_proof(tx, expected_upgrade)
    }
}
