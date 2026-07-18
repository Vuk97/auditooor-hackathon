pub struct Transaction;
pub struct PrecomputedTxData;
pub struct SigHash(pub [u8; 32]);
pub struct HashType;
pub struct Message;
pub struct Verifier;
pub struct Error;

impl Message {
    pub fn from_digest(_digest: [u8; 32]) -> Self {
        Message
    }
}

impl Verifier {
    pub fn verify_callback(&self, _msg: &Message) -> Result<(), Error> {
        Ok(())
    }
}

pub fn sighash(
    _precomputed: &PrecomputedTxData,
    _hash_type: HashType,
    _input: Option<(usize, Vec<u8>)>,
) -> SigHash {
    SigHash([0u8; 32])
}

pub fn verify_consensus_sighash_without_upgrade_scope(
    tx: &Transaction,
    input_index: usize,
    script_code: Vec<u8>,
    verifier: &Verifier,
) -> Result<(), Error> {
    let precomputed_tx_data = build_precomputed_tx_data(tx);
    let digest = sighash(&precomputed_tx_data, HashType, Some((input_index, script_code)));
    let msg = Message::from_digest(digest.0);
    verifier.verify_callback(&msg)?;
    Ok(())
}

fn build_precomputed_tx_data(_tx: &Transaction) -> PrecomputedTxData {
    PrecomputedTxData
}
