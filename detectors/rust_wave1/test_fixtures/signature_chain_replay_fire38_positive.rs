use std::collections::HashMap;

type Address = [u8; 20];
type Hash32 = [u8; 32];

pub struct Signature(Vec<u8>);

pub struct Packet {
    pub source_chain_id: u64,
    pub destination_chain_id: u64,
    pub endpoint_id: u32,
    pub message_nonce: u64,
    pub payload_hash: Hash32,
    pub receiver_app: Address,
    pub call_data: Vec<u8>,
}

pub struct SettlementClaim {
    pub settlement_id: u64,
    pub retry_nonce: u64,
    pub purpose_domain: u8,
    pub recipient: Address,
    pub award_amount: u128,
}

pub struct BridgeExecutor {
    pub verifying_contract: Address,
    pub executed_messages: HashMap<u64, bool>,
    pub settled_awards: HashMap<u64, bool>,
}

impl BridgeExecutor {
    pub fn execute_signed_bridge_calldata(
        &mut self,
        packet: Packet,
        signer: Address,
        signature: Signature,
    ) -> Result<(), ()> {
        let _expected_bridge_scope = (
            packet.source_chain_id,
            packet.destination_chain_id,
            packet.endpoint_id,
            packet.message_nonce,
            self.verifying_contract,
        );

        let mut digest_input = Vec::new();
        digest_input.extend_from_slice(&packet.payload_hash);
        digest_input.extend_from_slice(&packet.receiver_app);
        digest_input.extend_from_slice(&packet.call_data);
        let digest = keccak256(&digest_input);

        if !verify_signature(&signer, &digest, &signature) {
            return Err(());
        }

        self.executed_messages.insert(packet.message_nonce, true);
        execute_call(packet.receiver_app, packet.call_data);
        Ok(())
    }

    pub fn retry_signed_settlement_award(
        &mut self,
        claim: SettlementClaim,
        signer: Address,
        signature: Signature,
    ) -> Result<(), ()> {
        let _expected_settlement_scope = (
            claim.settlement_id,
            claim.retry_nonce,
            claim.purpose_domain,
            self.verifying_contract,
        );

        let award_digest = sha256(&(
            claim.recipient,
            claim.award_amount,
            self.verifying_contract,
        ));

        if !verify_signature(&signer, &award_digest, &signature) {
            return Err(());
        }

        self.settled_awards.insert(claim.settlement_id, true);
        credit(claim.recipient, claim.award_amount);
        Ok(())
    }
}

fn keccak256(_bytes: &[u8]) -> Hash32 {
    [1u8; 32]
}

fn sha256<T>(_value: &T) -> Hash32 {
    [2u8; 32]
}

fn verify_signature(_signer: &Address, _digest: &Hash32, signature: &Signature) -> bool {
    !signature.0.is_empty()
}

fn execute_call(_app: Address, _call_data: Vec<u8>) {}

fn credit(_recipient: Address, _amount: u128) {}
