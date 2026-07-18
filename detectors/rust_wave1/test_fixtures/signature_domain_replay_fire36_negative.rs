use std::collections::HashSet;

type Hash32 = [u8; 32];

pub struct BlsSignature(Vec<u8>);

pub struct FrostGroupKey;

impl FrostGroupKey {
    pub fn verify(&self, transcript: &[u8], signature: &BlsSignature) -> bool {
        let _ = (transcript.len(), signature.0.len());
        true
    }
}

pub struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            bytes: label.to_vec(),
        }
    }

    pub fn append_message(&mut self, _label: &'static [u8], data: &[u8]) {
        self.bytes.extend_from_slice(data);
    }

    pub fn append_u64(&mut self, _label: &'static [u8], value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn challenge_bytes(&self, _label: &'static [u8]) -> Vec<u8> {
        self.bytes.clone()
    }
}

pub struct SettlementRequest {
    pub payload_hash: Hash32,
    pub recipient: Hash32,
    pub amount: u64,
}

pub struct ThresholdSettlement {
    pub group_key: FrostGroupKey,
    pub executed_sessions: HashSet<Hash32>,
}

impl ThresholdSettlement {
    pub fn execute_frost_authorization(
        &mut self,
        chain_id: u64,
        domain_separator: Hash32,
        session_id: Hash32,
        purpose: u8,
        participant_set_hash: Hash32,
        request: SettlementRequest,
        signature: BlsSignature,
    ) -> Result<(), &'static str> {
        let mut transcript = Transcript::new(b"threshold-settlement");
        transcript.append_u64(b"chain", chain_id);
        transcript.append_message(b"domain", &domain_separator);
        transcript.append_message(b"session", &session_id);
        transcript.append_u64(b"purpose", purpose as u64);
        transcript.append_message(b"participants", &participant_set_hash);
        transcript.append_message(b"payload", &request.payload_hash);
        transcript.append_message(b"recipient", &request.recipient);
        transcript.append_u64(b"amount", request.amount);
        let transcript_bytes = transcript.challenge_bytes(b"bls-auth");

        if !self.group_key.verify(&transcript_bytes, &signature) {
            return Err("bad signature");
        }

        self.executed_sessions.insert(session_id);
        release_funds(request.recipient, request.amount);
        Ok(())
    }
}

fn release_funds(_recipient: Hash32, _amount: u64) {}
