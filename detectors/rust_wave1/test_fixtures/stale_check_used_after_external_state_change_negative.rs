pub struct RouteSettlement {
    routes: RouteBook,
    route_adapter: MutableRouteAdapter,
    vault: VaultLedger,
}

pub struct RouteBook;
pub struct MutableRouteAdapter;
pub struct VaultLedger;

pub struct Route {
    pub available: u64,
}

impl RouteBook {
    pub fn get(&self, _route_id: u64) -> Option<Route> {
        Some(Route { available: 100 })
    }

    pub fn reserve(&mut self, _route_id: u64, _amount: u64) {}

    pub fn consume(&mut self, _route_id: u64, _amount: u64) {}
}

impl MutableRouteAdapter {
    pub fn update_route(&self, _route_id: u64, _amount: u64) -> Result<(), ProgramError> {
        Ok(())
    }

    pub fn after_settlement(&self, _route_id: u64, _amount: u64) -> Result<(), ProgramError> {
        Ok(())
    }
}

impl VaultLedger {
    pub fn release(&mut self, _route_id: u64, _amount: u64) -> Result<(), ProgramError> {
        Ok(())
    }
}

pub enum ProgramError {
    InsufficientAvailable,
}

impl RouteSettlement {
    pub fn settle_with_revalidation(
        &mut self,
        route_id: u64,
        requested: u64,
    ) -> Result<(), ProgramError> {
        let checked_available = self.routes.get(route_id).unwrap().available;
        if checked_available < requested {
            return Err(ProgramError::InsufficientAvailable);
        }

        self.route_adapter.update_route(route_id, requested)?;

        let latest_available = self.routes.get(route_id).unwrap().available;
        if latest_available < requested {
            return Err(ProgramError::InsufficientAvailable);
        }

        self.vault.release(route_id, latest_available)?;
        self.routes.consume(route_id, requested);
        Ok(())
    }

    pub fn settle_finalize_before_route_update(
        &mut self,
        route_id: u64,
        requested: u64,
    ) -> Result<(), ProgramError> {
        let checked_available = self.routes.get(route_id).unwrap().available;
        if checked_available < requested {
            return Err(ProgramError::InsufficientAvailable);
        }

        self.routes.reserve(route_id, requested);
        self.vault.release(route_id, requested)?;
        self.route_adapter.after_settlement(route_id, requested)?;
        Ok(())
    }
}
