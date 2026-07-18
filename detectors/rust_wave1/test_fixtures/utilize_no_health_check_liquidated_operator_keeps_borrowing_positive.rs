use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct Operator {
    pub collateral: u64,
    pub borrowed: u64,
    pub is_liquidated: bool,
}

pub struct LendingPool {
    operators: HashMap<u64, Operator>,
    min_health_factor: u64,
}

impl LendingPool {
    pub fn new() -> Self {
        Self {
            operators: HashMap::new(),
            min_health_factor: 150,
        }
    }

    pub fn register_operator(&mut self, id: u64, collateral: u64) {
        self.operators.insert(id, Operator {
            collateral,
            borrowed: 0,
            is_liquidated: false,
        });
    }

    pub fn liquidate_operator(&mut self, id: u64) -> Result<(), &'static str> {
        let op = self.operators.get_mut(&id).ok_or("operator not found")?;
        let health = self.calculate_health_factor(op.collateral, op.borrowed);
        if health >= self.min_health_factor {
            return Err("operator is healthy");
        }
        op.is_liquidated = true;
        Ok(())
    }

    fn calculate_health_factor(&self, collateral: u64, borrowed: u64) -> u64 {
        if borrowed == 0 {
            return u64::MAX;
        }
        (collateral * 100) / borrowed
    }

    fn check_health_factor(&self, operator: &Operator, amount: u64) -> Result<(), &'static str> {
        // Only checks health, NOT liquidation status
        let new_borrowed = operator.borrowed + amount;
        let health = self.calculate_health_factor(operator.collateral, new_borrowed);
        if health < self.min_health_factor {
            return Err("insufficient health factor");
        }
        Ok(())
    }

    pub fn utilize(&mut self, operator_id: u64, amount: u64) -> Result<(), &'static str> {
        let operator = self.operators.get(&operator_id).ok_or("operator not found")?;
        
        // BUG: Only checks health factor, skips is_liquidated check!
        self.check_health_factor(operator, amount)?;
        // Missing: if operator.is_liquidated { return Err(...); }
        
        let operator = self.operators.get_mut(&operator_id).unwrap();
        operator.borrowed += amount;
        Ok(())
    }

    pub fn utilize_while_adding_keys(
        &mut self,
        operator_id: u64,
        amount: u64,
        _new_keys: Vec<u64>,
    ) -> Result<(), &'static str> {
        let operator = self.operators.get(&operator_id).ok_or("operator not found")?;
        
        // BUG: Same vulnerability - only health check, no liquidation check
        self.check_health_factor(operator, amount)?;
        // Missing: if operator.is_liquidated { return Err(...); }
        
        let operator = self.operators.get_mut(&operator_id).unwrap();
        operator.borrowed += amount;
        Ok(())
    }
}

fn main() {
    let mut pool = LendingPool::new();
    pool.register_operator(1, 1000);
    pool.utilize(1, 600).unwrap();
    
    // Liquidate the operator (health drops below 150%)
    pool.liquidate_operator(1).unwrap();
    
    // BUG: Liquidated operator can still borrow!
    // This should fail but succeeds in vulnerable version
    pool.utilize(1, 100).unwrap(); // No error - funds drained
    
    // Same bug in utilize_while_adding_keys
    pool.utilize_while_adding_keys(1, 50, vec![1, 2, 3]).unwrap();
}