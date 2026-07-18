pub struct Network;

#[derive(Clone, Copy)]
pub struct Height(pub u32);

#[derive(Clone, Copy)]
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

pub struct Validator {
    pub network: Network,
    pub tip_height: Height,
}

impl BranchId {
    pub fn current(_network: &Network, _height: Height) -> BranchId {
        BranchId(0xc2d6_d0b4)
    }
}

impl Transaction {
    pub fn network_upgrade(&self) -> Option<NetworkUpgrade> {
        None
    }
}

pub fn verify_sighash(_tx: &Transaction, _branch: BranchId) -> Result<(), ()> {
    Ok(())
}

pub fn verify_orchard_proof(_tx: &Transaction, _upgrade: NetworkUpgrade) -> Result<(), ()> {
    Ok(())
}

impl Validator {
    pub fn validate_transaction_at_tip(&self, tx: &Transaction) -> Result<(), ()> {
        let object_branch = tx.branch_id;
        let local_branch = BranchId::current(&self.network, self.tip_height);
        let _ = object_branch;
        verify_sighash(tx, local_branch)
    }

    pub fn validate_orchard_bundle_default(tx: &Transaction) -> Result<(), ()> {
        let selected_upgrade = tx.network_upgrade().unwrap_or(NetworkUpgrade::Nu5);
        verify_orchard_proof(tx, selected_upgrade)
    }
}
