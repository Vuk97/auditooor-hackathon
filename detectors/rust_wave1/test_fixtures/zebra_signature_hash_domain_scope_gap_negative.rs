pub enum NetworkUpgrade {
    Canopy,
    Nu5,
}

pub struct Transaction;
pub struct SigHasher;
pub struct SigHash(pub [u8; 32]);
pub struct HashType;

impl Transaction {
    pub fn version(&self) -> u32 {
        5
    }
}

impl SigHasher {
    pub fn sighash_v4_raw(
        &self,
        _raw_hash_type: u8,
        _input: Option<(usize, Vec<u8>)>,
    ) -> SigHash {
        SigHash([0u8; 32])
    }

    pub fn sighash(
        &self,
        _hash_type: HashType,
        _input: Option<(usize, Vec<u8>)>,
    ) -> SigHash {
        SigHash([1u8; 32])
    }
}

pub fn verify_consensus_sighash_with_upgrade_scope(
    tx: &Transaction,
    nu: NetworkUpgrade,
    sighasher: &SigHasher,
    input_index: usize,
    script_code: Vec<u8>,
) -> SigHash {
    match nu {
        NetworkUpgrade::Canopy if tx.version() < 5 => {
            sighasher.sighash_v4_raw(0x41, Some((input_index, script_code)))
        }
        NetworkUpgrade::Nu5 => sighasher.sighash(HashType, Some((input_index, script_code))),
        _ => sighasher.sighash(HashType, Some((input_index, script_code))),
    }
}
