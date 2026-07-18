use std::collections::BTreeMap;

#[derive(Clone)]
pub struct Address([u8; 32]);

pub struct RouteConfig {
    pub gateway: Address,
    pub admin: Address,
}

pub struct BridgeRegistry {
    pub routes: BTreeMap<(u64, u64), RouteConfig>,
    pub gateway_for: BTreeMap<u64, Address>,
    pub route_created: BTreeMap<(u64, u64), bool>,
}

impl BridgeRegistry {
    pub fn setup_route(
        &mut self,
        source_chain_id: u64,
        destination_chain_id: u64,
        gateway: Address,
        admin: Address,
    ) {
        let route_key = (source_chain_id, destination_chain_id);
        if self.routes.contains_key(&route_key) {
            panic!("route exists");
        }

        self.routes.insert(
            route_key,
            RouteConfig {
                gateway: gateway.clone(),
                admin,
            },
        );
        self.gateway_for.insert(destination_chain_id, gateway);
        self.route_created.insert(route_key, true);
    }
}
