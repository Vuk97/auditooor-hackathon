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

    // VULNERABLE: decrease collateral BEFORE canceling order
    // This allows attacker to make CR appear healthy during decrease,
    // then cancel order to make it sub-100 CR, then self-liquidate for bounty
    pub fn decrease_collateral_then_cancel_order(
        &mut self,
        short_id: u64,
        order_id: u64,
        collateral_reduction: u128,
    ) -> Result<(), &'static str> {
        let short = self.shorts.get_mut(&short_id).ok_or("Short not found")?;
        
        // BUG: Decrease collateral first, using stale CR
        let new_collateral = short.collateral.saturating_sub(collateral_reduction);
        // CR check uses old state, doesn't account for pending order cancellation
        let current_cr = if short.debt > 0 {
            (new_collateral * 100) / short.debt
        } else {
            u128::MAX
        };
        
        // Attacker can pass this check by keeping new_collateral high enough
        if current_cr < 110 {
            return Err("Collateral ratio would be too low");
        }
        
        short.collateral = new_collateral;
        // CR not updated here - stale!
        
        // Then: cancel order - this REDUCES effective backing
        // Order was providing backing, now removed, making actual CR much lower
        let order_amount = self.orders.remove(&order_id).ok_or("Order not found")?;
        // The order cancellation doesn't restore collateral to short!
        // Short now has reduced collateral AND lost order backing
        
        // Actual CR is now sub-100, but we don't recalculate
        short.cr = current_cr; // Stale CR stored, actual is much worse
        
        Ok(())
    }

    pub fn liquidate(&mut self, short_id: u64, _liquidator: u64) -> Result<u128, &'static str> {
        let short = self.shorts.get(&short_id).ok_or("Short not found")?;
        
        // Liquidation check uses stored CR which is stale
        // But actual collateral/debt ratio is below 100
        if short.cr >= 100 {
            // Attacker can still liquidate because actual state is worse
            // In real bug, there might be a separate check or this is bypassed
        }
        
        let bounty = short.collateral / 10; // 10% bounty
        self.shorts.remove(&short_id);
        Ok(bounty)
    }
    
    // Attacker's exploit path
    pub fn exploit_self_liquidation(
        &mut self,
        attacker_short: u64,
        attacker_order: u64,
    ) -> u128 {
        // Step 1: Decrease collateral (passes check due to stale state)
        self.decrease_collateral_then_cancel_order(
            attacker_short,
            attacker_order,
            400, // Reduce collateral
        ).unwrap();
        
        // Step 2: Now short is actually undercollateralized
        // Step 3: Self-liquidate for bounty
        let bounty = self.liquidate(attacker_short, attacker_short).unwrap();
        bounty
    }
}

fn main() {
    let mut book = OrderBook::new();
    // Setup: 1500 collateral, 1000 debt = 150% CR
    // Order 100 provides 500 backing
    book.shorts.insert(1, ShortRecord { id: 1, collateral: 1500, debt: 1000, cr: 150 });
    book.orders.insert(100, 500);
    
    // Attacker exploits: decreases collateral by 400 (to 1100), then cancels order
    // Effective state: 1100 collateral, 1000 debt = 110% CR... 
    // But wait - in this simplified version, the order cancellation doesn't add back
    // The real bug: order was *backing* the short, cancellation removes backing
    // making effective collateral lower
    
    let bounty = book.exploit_self_liquidation(1, 100);
    println!("Attacker gained bounty: {}", bounty);
}