pub struct SettlementEngine {
    orders: OrderBook,
    settlement_hook: UserSettlementHook,
    vault: VaultLedger,
}

pub struct OrderBook;
pub struct UserSettlementHook;
pub struct VaultLedger;

pub struct Order {
    pub remaining: u64,
}

impl OrderBook {
    pub fn get(&self, _order_id: u64) -> Option<Order> {
        Some(Order { remaining: 100 })
    }

    pub fn mark_filled(&mut self, _order_id: u64, _amount: u64) {}
}

impl UserSettlementHook {
    pub fn before_settlement(&self, _order_id: u64, _amount: u64) -> Result<(), ProgramError> {
        Ok(())
    }
}

impl VaultLedger {
    pub fn release(&mut self, _order_id: u64, _amount: u64) -> Result<(), ProgramError> {
        Ok(())
    }
}

pub enum ProgramError {
    InsufficientRemaining,
}

impl SettlementEngine {
    pub fn settle_with_hook(&mut self, order_id: u64, requested: u64) -> Result<(), ProgramError> {
        let pre_checked_remaining = self.orders.get(order_id).unwrap().remaining;
        if pre_checked_remaining < requested {
            return Err(ProgramError::InsufficientRemaining);
        }

        self.settlement_hook.before_settlement(order_id, requested)?;

        self.vault.release(order_id, pre_checked_remaining)?;
        self.orders.mark_filled(order_id, requested);
        Ok(())
    }
}
