pub struct Bridge {
    pub trusted_routes: RouteTable,
    pub trusted_signer: u64,
    pub relayers: RelayerSet,
}

pub struct BridgeMessage {
    pub kind: MessageKind,
    pub destination_chain: u64,
    pub route: u64,
    pub new_signer: u64,
}

pub enum MessageKind {
    RouteUpdate,
    SignerSwap,
    RelayerAction,
}

impl Bridge {
    pub fn receive_message(&mut self, caller: u64, msg: BridgeMessage) {
        require_bridge_authority(caller);

        match msg.kind {
            MessageKind::RouteUpdate => {
                self.trusted_routes.insert(msg.destination_chain, msg.route);
            }
            MessageKind::SignerSwap => {
                self.trusted_signer = msg.new_signer;
                self.trusted_routes.insert(msg.destination_chain, msg.route);
            }
            MessageKind::RelayerAction => {
                self.relayers.insert(caller);
            }
        }
    }
}

pub struct RouteTable;
impl RouteTable {
    pub fn insert(&mut self, _chain: u64, _route: u64) {}
}

pub struct RelayerSet;
impl RelayerSet {
    pub fn insert(&mut self, _relayer: u64) {}
}

fn require_bridge_authority(_caller: u64) {}
