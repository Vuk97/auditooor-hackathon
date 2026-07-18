use std::collections::{HashMap, HashSet};

type Hash32 = [u8; 32];

pub struct LightClient {
    accepted_roots: HashMap<(u64, Hash32), Hash32>,
    consumed_commitments: HashSet<Hash32>,
}

impl LightClient {
    pub fn submit_light_client_update(
        &mut self,
        chain_id: u32,
        client_id: u64,
        pallet_id: Hash32,
        gateway: Hash32,
        channel_id: u32,
        nonce_lane: u64,
        state_root: Hash32,
        message_commitment: Hash32,
        validator_set_hash: Hash32,
        proof_digest: Hash32,
        proof: Vec<Hash32>,
    ) -> Result<(), &'static str> {
        let _visible_replay_domain = (
            chain_id,
            client_id,
            pallet_id,
            gateway,
            channel_id,
            nonce_lane,
        );

        let mut authenticated_bytes = Vec::new();
        authenticated_bytes.extend_from_slice(&state_root);
        authenticated_bytes.extend_from_slice(&message_commitment);
        authenticated_bytes.extend_from_slice(&validator_set_hash);
        authenticated_bytes.extend_from_slice(&proof_digest);
        let accepted_digest = blake2b(&authenticated_bytes);

        if !verify_light_client_proof(&accepted_digest, &proof) {
            return Err("bad proof");
        }

        self.accepted_roots
            .insert((nonce_lane, state_root), message_commitment);
        self.consumed_commitments.insert(accepted_digest);
        Ok(())
    }
}

fn verify_light_client_proof(_digest: &Hash32, _proof: &[Hash32]) -> bool {
    true
}

fn blake2b(_input: &[u8]) -> Hash32 {
    [0u8; 32]
}
