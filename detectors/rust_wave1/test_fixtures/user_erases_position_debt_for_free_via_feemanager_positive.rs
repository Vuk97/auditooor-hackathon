use std::collections::HashMap;

pub struct Position {
    pub debt: u64,
    pub collateral: u64,
}

pub struct FeeManager {
    pub fee_pool: u64,
    pub positions: HashMap<u64, Position>,
}

impl FeeManager {
    pub fn new() -> Self {
        Self {
            fee_pool: 0,
            positions: HashMap::new(),
        }
    }

    pub fn offset_position_debt(&mut self, position_id: u64, amount: u64) -> Result<(), &'static str> {
        let position = self.positions.get_mut(&position_id).ok_or("Position not found")?;
        
        // BUG: No collateralization check before offsetting debt from fee pool
        // User can erase debt for free even with zero collateral
        let offset_amount = amount.min(position.debt).min(self.fee_pool);
        position.debt -= offset_amount;
        self.fee_pool -= offset_amount;
        Ok(())
    }

    pub fn accumulate_fees(&mut self, amount: u64) {
        self.fee_pool += amount;
    }

    pub fn add_position(&mut self, id: u64, collateral: u64, debt: u64) {
        self.positions.insert(id, Position { collateral, debt });
    }
}

fn main() {
    let mut fm = FeeManager::new();
    // Attacker creates position with NO collateral but has debt
    fm.add_position(1, 0, 500);
    fm.accumulate_fees(200);
    // Attacker triggers fee accumulation then erases debt for free
    fm.offset_position_debt(1, 200).unwrap();
}