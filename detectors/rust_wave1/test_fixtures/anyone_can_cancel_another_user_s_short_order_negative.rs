use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
struct Order {
    owner: u64,
    is_cancelled: bool,
}

#[derive(Clone, Debug, Default)]
struct ShortRecord {
    owner: u64,
    short_order_id: u64,
}

struct OrderBook {
    orders: HashMap<u64, Order>,
    next_order_id: u64,
}

impl OrderBook {
    fn new() -> Self {
        Self {
            orders: HashMap::new(),
            next_order_id: 1,
        }
    }

    fn create_order(&mut self, owner: u64) -> u64 {
        let id = self.next_order_id;
        self.next_order_id += 1;
        self.orders.insert(id, Order { owner, is_cancelled: false });
        id
    }

    fn cancel_order(&mut self, caller: u64, order_id: u64) -> Result<(), &'static str> {
        let order = self.orders.get_mut(&order_id).ok_or("Order not found")?;
        if order.owner != caller {
            return Err("Not order owner");
        }
        order.is_cancelled = true;
        Ok(())
    }

    fn transfer_short_record(
        &mut self,
        caller: u64,
        short_record: &mut ShortRecord,
        new_owner: u64,
        new_short_order_id: u64,
    ) -> Result<(), &'static str> {
        if short_record.owner != caller {
            return Err("Not short record owner");
        }
        
        // Verify caller owns the new short order before transfer
        let new_order = self.orders.get(&new_short_order_id).ok_or("Order not found")?;
        if new_order.owner != caller {
            return Err("Not owner of new short order");
        }
        
        short_record.owner = new_owner;
        short_record.short_order_id = new_short_order_id;
        Ok(())
    }
}

fn main() {
    let mut book = OrderBook::new();
    let alice = 1u64;
    let bob = 2u64;
    
    let order1 = book.create_order(alice);
    let order2 = book.create_order(bob);
    
    let mut short = ShortRecord { owner: alice, short_order_id: order1 };
    
    // Alice can transfer her own short record with her own order
    assert!(book.transfer_short_record(alice, &mut short, bob, order1).is_ok());
    
    // Bob cannot cancel Alice's order
    assert!(book.cancel_order(bob, order2).is_ok());
    assert!(book.cancel_order(bob, order1).is_err());
}