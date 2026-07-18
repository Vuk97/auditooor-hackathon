pub struct Bridge {
    pub allowed_channels: ChannelAllowlist,
    pub processed: ProcessedSet,
    pub outbox: Outbox,
    pub nft: Nft,
    pub escrow: Address,
}

impl Bridge {
    pub fn bridge_nft(
        &mut self,
        env: Env,
        owner: Address,
        destination_chain: u32,
        channel_id: u32,
        destination: Address,
        token_id: u64,
        payload: Bytes,
    ) {
        if !self.allowed_channels.contains(&(destination_chain, channel_id)) {
            panic!("unsupported route");
        }

        let token_owner = self.nft.owner_of(token_id);
        if token_owner != owner {
            panic!("wrong owner");
        }
        token_owner.require_auth_for_args((
            destination_chain,
            channel_id,
            destination.clone(),
            token_id,
            payload_hash(&payload),
        ));

        let message_id = sha256(&(
            b"BRIDGE_DESTINATION_AUTH_V1",
            token_owner.clone(),
            destination_chain,
            channel_id,
            destination.clone(),
            token_id,
            payload_hash(&payload),
        ));
        if self.processed.contains(&message_id) {
            panic!("already sent");
        }
        self.processed.insert(message_id.clone(), true);

        self.nft.transfer_from(&token_owner, &self.escrow, token_id);
        self.outbox.push(OutboundMessage {
            id: message_id,
            destination_chain,
            channel_id,
            destination,
            token_id,
        });

        env.events().publish(("bridge", token_id), destination_chain);
    }
}

pub struct Env;
impl Env {
    pub fn events(&self) -> Events {
        Events
    }
}
pub struct Events;
impl Events {
    pub fn publish<T, U>(&self, _topic: T, _value: U) {}
}

#[derive(Clone, PartialEq, Eq)]
pub struct Address;
impl Address {
    pub fn require_auth_for_args<T>(&self, _args: T) {}
}

pub struct Bytes;
pub struct ChannelAllowlist;
impl ChannelAllowlist {
    pub fn contains(&self, _route: &(u32, u32)) -> bool {
        true
    }
}

pub struct ProcessedSet;
impl ProcessedSet {
    pub fn contains(&self, _id: &[u8; 32]) -> bool {
        false
    }
    pub fn insert(&mut self, _id: [u8; 32], _used: bool) {}
}

pub struct Outbox;
impl Outbox {
    pub fn push(&mut self, _message: OutboundMessage) {}
}

pub struct OutboundMessage {
    pub id: [u8; 32],
    pub destination_chain: u32,
    pub channel_id: u32,
    pub destination: Address,
    pub token_id: u64,
}

pub struct Nft;
impl Nft {
    pub fn owner_of(&self, _token_id: u64) -> Address {
        Address
    }
    pub fn transfer_from(&self, _from: &Address, _to: &Address, _token_id: u64) {}
}

pub fn payload_hash(_payload: &Bytes) -> [u8; 32] {
    [0u8; 32]
}

pub fn sha256<T>(_input: &T) -> [u8; 32] {
    [0u8; 32]
}
