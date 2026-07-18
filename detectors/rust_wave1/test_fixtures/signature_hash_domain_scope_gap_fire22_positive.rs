pub struct Transaction {
    pub id: [u8; 32],
}

pub struct Message;
pub struct Verifier;
pub struct Error;

pub fn hash(_bytes: &[u8]) -> [u8; 32] {
    [0u8; 32]
}

impl Message {
    pub fn from_digest(_digest: [u8; 32]) -> Self {
        Message
    }
}

impl Verifier {
    pub fn verify_callback(&self, _message: &Message) -> Result<(), Error> {
        Ok(())
    }
}

pub fn verify_cross_scope_signature_digest_missing_fields(
    tx: &Transaction,
    network_id: u32,
    branch_id: u32,
    entrypoint_id: u32,
    transparent_scope: [u8; 32],
    shielded_scope: [u8; 32],
    tx_context: u64,
    payload: &[u8],
    verifier: &Verifier,
) -> Result<(), Error> {
    let _available_scope = (
        network_id,
        branch_id,
        entrypoint_id,
        transparent_scope,
        shielded_scope,
        tx_context,
    );

    let mut digest_material = Vec::new();
    digest_material.extend_from_slice(&tx.id);
    digest_material.extend_from_slice(payload);

    let message = Message::from_digest(hash(&digest_material));
    verifier.verify_callback(&message)?;
    Ok(())
}
