use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OrderStatus {
    Open,
    PartiallyMatched,
    Closed,
}

#[derive(Clone, Debug)]
pub struct Order {
    pub id: u64,
    pub collateral_locked: u128,
    pub debt_minted: u128,
    pub status: OrderStatus,
}

pub struct OrderBook {
    orders: HashMap<u64, Order>,
    pub total_collateral: u128,
    pub total_debt: u128,
}

impl OrderBook {
    pub fn new() -> Self {
        Self {
            orders: HashMap::new(),
            total_collateral: 0,
            total_debt: 0,
        }
    }

    pub fn create_order(&mut self, id: u64, collateral: u128, debt: u128) {
        assert!(collateral >= debt * 15 / 10, "Insufficient collateral");
        let order = Order {
            id,
            collateral_locked: collateral,
            debt_minted: debt,
            status: OrderStatus::Open,
        };
        self.total_collateral += collateral;
        self.total_debt += debt;
        self.orders.insert(id, order);
    }

    pub fn partial_match(&mut self, id: u64, matched_debt: u128, matched_collateral: u128) {
        let order = self.orders.get_mut(&id).expect("Order not found");
        assert!(order.status == OrderStatus::Open || order.status == OrderStatus::PartiallyMatched);
        order.debt_minted -= matched_debt;
        order.collateral_locked -= matched_collateral;
        order.status = OrderStatus::PartiallyMatched;
        self.total_debt -= matched_debt;
        self.total_collateral -= matched_collateral;
    }

    pub fn cancel_order(&mut self, id: u64) -> Option<Order> {
        let order = self.orders.get(&id)?;
        
        // Always reconcile remaining collateral before removing
        let remaining_collateral = order.collateral_locked;
        let remaining_debt = order.debt_minted;
        
        self.total_collateral -= remaining_collateral;
        self.total_debt -= remaining_debt;
        
        // Refund remaining collateral to user (in real system, transfer tokens)
        // Then remove the order
        self.orders.remove(&id)
    }

    pub fn get_order(&self, id: u64) -> Option<&Order> {
        self.orders.get(&id)
    }
}

fn main() {
    let mut book = OrderBook::new();
    book.create_order(1, 1500, 1000);
    book.partial_match(1, 400, 600);
    
    let cancelled = book.cancel_order(1);
    assert!(cancelled.is_some());
    assert_eq!(book.total_collateral, 0);
    assert_eq!(book.total_debt, 0);
    println!("Clean: collateral properly reconciled on cancel");
}