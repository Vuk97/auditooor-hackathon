pub struct SettlementEngine {
    orders: OrderBook,
    hook: UserHook,
    token_program: TokenProgram,
}

pub struct OrderBook;
pub struct UserHook;
pub struct TokenProgram;

pub struct Order {
    pub remaining: u64,
}

impl OrderBook {
    pub fn get(&self, _order_id: u64) -> Option<Order> {
        Some(Order { remaining: 100 })
    }

    pub fn debit(&mut self, _order_id: u64, _amount: u64) {}
}

impl UserHook {
    pub fn before_settlement(&self, _order_id: u64, _amount: u64) -> Result<(), ProgramError> {
        Ok(())
    }
}

impl TokenProgram {
    pub fn transfer_from_vault(&self, _order_id: u64, _amount: u64) -> Result<(), ProgramError> {
        Ok(())
    }
}

pub enum ProgramError {
    InsufficientRemaining,
}

impl SettlementEngine {
    pub fn settle_order(&mut self, order_id: u64, requested: u64) -> Result<(), ProgramError> {
        let cached_remaining = self.orders.get(order_id).unwrap().remaining;
        if cached_remaining < requested {
            return Err(ProgramError::InsufficientRemaining);
        }

        self.hook.before_settlement(order_id, requested)?;

        let latest_remaining = self.orders.get(order_id).unwrap().remaining;
        if latest_remaining < requested {
            return Err(ProgramError::InsufficientRemaining);
        }

        self.token_program.transfer_from_vault(order_id, latest_remaining)?;
        self.orders.debit(order_id, requested);
        Ok(())
    }
}
