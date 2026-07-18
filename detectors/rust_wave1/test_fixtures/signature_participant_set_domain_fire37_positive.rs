use std::collections::HashSet;

type Hash32 = [u8; 32];

pub struct FrostSignature(Vec<u8>);

pub struct FrostGroupKey;

impl FrostGroupKey {
    pub fn verify(&self, transcript: &[u8], signature: &FrostSignature) -> bool {
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

pub struct ReleasePayload {
    pub payload_hash: Hash32,
    pub recipient: Hash32,
    pub amount: u64,
}

pub struct ThresholdRelease {
    pub group_key: FrostGroupKey,
    pub completed_sessions: HashSet<Hash32>,
}

impl ThresholdRelease {
    pub fn execute_frost_threshold_release(
        &mut self,
        chain_id: u64,
        participant_set_hash: Hash32,
        signer_role: u8,
        threshold: u16,
        session_id: Hash32,
        purpose_domain: u8,
        payload: ReleasePayload,
        signature: FrostSignature,
    ) -> Result<(), &'static str> {
        let _replay_scope = (
            chain_id,
            participant_set_hash,
            signer_role,
            threshold,
            session_id,
            purpose_domain,
        );

        let mut transcript = Transcript::new(b"frost-release");
        transcript.append_message(b"payload", &payload.payload_hash);
        transcript.append_message(b"recipient", &payload.recipient);
        transcript.append_u64(b"amount", payload.amount);
        let transcript_bytes = transcript.challenge_bytes(b"frost-auth");

        if !self.group_key.verify(&transcript_bytes, &signature) {
            return Err("bad signature");
        }

        self.completed_sessions.insert(session_id);
        release_assets(payload.recipient, payload.amount);
        Ok(())
    }
}

fn release_assets(_recipient: Hash32, _amount: u64) {}
