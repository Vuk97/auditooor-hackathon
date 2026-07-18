use std::collections::HashMap;

pub struct ShortRecord {
    pub collateral: u64,
    pub debt: u64,
}

pub struct MarketState {
    pub shorts: HashMap<u64, ShortRecord>,
    pub balances: HashMap<u64, u64>,
}

impl MarketState {
    pub fn new() -> Self {
        Self {
            shorts: HashMap::new(),
            balances: HashMap::new(),
        }
    }

    pub fn exit_short(&mut self, short_id: u64, caller: u64, payout: u64) -> Result<(), &'static str> {
        let sr = self.shorts.remove(&short_id).ok_or("short not found")?;
        
        // Return collateral to shorter before transferring payout
        let caller_balance = self.balances.entry(caller).or_insert(0);
        *caller_balance = caller_balance.checked_add(sr.collateral).ok_or("overflow")?;
        
        // Transfer payout to appropriate party
        let payout_balance = self.balances.entry(caller).or_insert(0);
        *payout_balance = payout_balance.checked_add(payout).ok_or("overflow")?;
        
        Ok(())
    }
}

fn main() {
    let mut state = MarketState::new();
    state.shorts.insert(1, ShortRecord { collateral: 1000, debt: 500 });
    state.balances.insert(42, 0);
    state.exit_short(1, 42, 300).unwrap();
    assert_eq!(state.balances[&42], 1300); // 1000 collateral + 300 payout
}