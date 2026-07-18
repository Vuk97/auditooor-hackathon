use std::collections::BTreeMap;

#[derive(Clone)]
pub struct Address([u8; 32]);

impl Address {
    pub fn require_auth(&self) {}
}

pub enum RouteError {
    SameChain,
    RouteExists,
}

pub struct RouteConfig {
    pub gateway: Address,
    pub admin: Address,
}

pub struct BridgeRegistry {
    pub routes: BTreeMap<(u64, u64), RouteConfig>,
    pub gateway_for: BTreeMap<u64, Address>,
}

impl BridgeRegistry {
    pub fn setup_route(
        &mut self,
        admin: Address,
        source_chain_id: u64,
        destination_chain_id: u64,
        gateway: Address,
    ) -> Result<(), RouteError> {
        admin.require_auth();
        if source_chain_id == destination_chain_id {
            return Err(RouteError::SameChain);
        }

        let route_key = (source_chain_id, destination_chain_id);
        if self.routes.contains_key(&route_key) {
            return Err(RouteError::RouteExists);
        }

        self.routes.insert(
            route_key,
            RouteConfig {
                gateway: gateway.clone(),
                admin,
            },
        );
        self.gateway_for.insert(destination_chain_id, gateway);
        Ok(())
    }
}
