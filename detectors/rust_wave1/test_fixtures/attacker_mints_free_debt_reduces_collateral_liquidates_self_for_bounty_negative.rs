use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct ShortRecord {
    pub id: u64,
    pub collateral: u128,
    pub debt: u128,
    pub cr: u128, // collateral ratio
}

pub struct OrderBook {
    pub shorts: HashMap<u64, ShortRecord>,
    pub orders: HashMap<u64, u128>, // order_id -> amount
}

impl OrderBook {
    pub fn new() -> Self {
        Self {
            shorts: HashMap::new(),
            orders: HashMap::new(),
        }
    }

    // CLEAN: Proper ordering - cancel order first, then adjust collateral
    pub fn cancel_order_then_decrease_collateral(
        &mut self,
        short_id: u64,
        order_id: u64,
        collateral_reduction: u128,
    ) -> Result<(), &'static str> {
        let short = self.shorts.get_mut(&short_id).ok_or("Short not found")?;
        
        // First: cancel the order (restores backing to short)
        let order_amount = self.orders.remove(&order_id).ok_or("Order not found")?;
        short.collateral = short.collateral.saturating_add(order_amount);
        
        // Then: safely decrease collateral with updated CR check
        let new_collateral = short.collateral.saturating_sub(collateral_reduction);
        let new_cr = if short.debt > 0 {
            (new_collateral * 100) / short.debt
        } else {
            u128::MAX
        };
        
        // Enforce minimum collateral ratio (e.g., 110%)
        if new_cr < 110 {
            return Err("Collateral ratio would be too low");
        }
        
        short.collateral = new_collateral;
        short.cr = new_cr;
        
        Ok(())
    }

    pub fn liquidate(&mut self, short_id: u64, _liquidator: u64) -> Result<u128, &'static str> {
        let short = self.shorts.get(&short_id).ok_or("Short not found")?;
        
        // Only liquidate if actually undercollateralized
        if short.cr >= 100 {
            return Err("Not liquidatable");
        }
        
        let bounty = short.collateral / 10; // 10% bounty
        self.shorts.remove(&short_id);
        Ok(bounty)
    }
}

fn main() {
    let mut book = OrderBook::new();
    book.shorts.insert(1, ShortRecord { id: 1, collateral: 1500, debt: 1000, cr: 150 });
    book.orders.insert(100, 500);
    
    // Clean path: cancel first, then decrease
    let result = book.cancel_order_then_decrease_collateral(1, 100, 400);
    assert!(result.is_ok());
    
    let short = book.shorts.get(&1).unwrap();
    assert!(short.cr >= 110); // Still healthy
}