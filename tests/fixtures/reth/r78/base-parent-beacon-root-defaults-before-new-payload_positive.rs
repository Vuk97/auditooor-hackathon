pub struct InsertTask {
    envelope: Envelope,
    client: EngineClient,
}

pub struct Envelope {
    parent_beacon_block_root: Option<[u8; 32]>,
}

pub struct EngineClient;

impl EngineClient {
    pub async fn new_payload_v4(&self, _root: [u8; 32]) {}
}

impl InsertTask {
    pub async fn execute(&self) {
        let parent_beacon_block_root = self.envelope.parent_beacon_block_root.unwrap_or_default();
        self.client.new_payload_v4(parent_beacon_block_root).await;
    }
}
