use std::collections::BTreeSet;

pub struct ReceiptProof {
    pub proof_root: [u8; 32],
    pub receipt: [u8; 32],
    pub payload_hash: [u8; 32],
    pub proof: Vec<[u8; 32]>,
}

pub struct BridgeReceiptVerifier;

impl BridgeReceiptVerifier {
    pub fn verify_bridge_receipt_proof(
        proof: ReceiptProof,
        source_domain: u32,
        destination_domain: u32,
        receiver_domain: [u8; 32],
        light_client_id: u64,
        consumed_receipts: &mut BTreeSet<[u8; 32]>,
    ) -> bool {
        let accepted_leaf = blake2b(&(
            source_domain,
            destination_domain,
            receiver_domain,
            light_client_id,
            proof.proof_root,
            proof.receipt,
            proof.payload_hash,
        ));

        if verify_merkle(proof.proof_root, accepted_leaf, proof.proof) {
            consumed_receipts.insert(accepted_leaf);
            true
        } else {
            false
        }
    }
}

fn blake2b<T>(_parts: &T) -> [u8; 32] {
    [0u8; 32]
}

fn verify_merkle(_root: [u8; 32], _leaf: [u8; 32], _proof: Vec<[u8; 32]>) -> bool {
    true
}
