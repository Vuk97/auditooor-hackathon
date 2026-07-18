use std::collections::HashMap;

pub struct BridgeRelay {
    verifier: Verifier,
    pending_messages: HashMap<(u64, u64, [u8; 32], u64), QueuedMessage>,
}

pub struct Verifier;
pub struct Proof;

pub struct BridgeMessage {
    pub nonce: u64,
    pub payload_hash: [u8; 32],
    pub receiver: [u8; 32],
}

pub struct QueuedMessage {
    pub payload_hash: [u8; 32],
    pub receiver: [u8; 32],
}

impl BridgeRelay {
    pub fn relay_verified_bridge_message(
        &mut self,
        source_chain: u64,
        destination_chain: u64,
        receiver_domain: [u8; 32],
        proof: Proof,
        message: BridgeMessage,
    ) -> Result<(), Error> {
        let message_digest = sha256(&(
            source_chain,
            destination_chain,
            receiver_domain,
            message.nonce,
            message.payload_hash,
        ));
        if !self.verifier.verify_message(&proof, message_digest) {
            return Err(Error::BadProof);
        }

        self.pending_messages.insert(
            (
                source_chain,
                destination_chain,
                receiver_domain,
                message.nonce,
            ),
            QueuedMessage {
                payload_hash: message.payload_hash,
                receiver: message.receiver,
            },
        );
        Ok(())
    }
}

impl Verifier {
    pub fn verify_message(&self, _proof: &Proof, _digest: [u8; 32]) -> bool {
        true
    }
}

pub enum Error {
    BadProof,
}

fn sha256<T>(_parts: &T) -> [u8; 32] {
    [0u8; 32]
}
