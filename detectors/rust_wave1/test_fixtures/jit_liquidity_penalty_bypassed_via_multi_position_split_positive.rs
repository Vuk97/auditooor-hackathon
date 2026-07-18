use std::collections::HashMap;

/// Tracks JIT liquidity penalties per pool + owner + salt.
/// VULNERABLE: penalty is tracked per-salt, allowing bypass via
/// multiple positions with different salts.
#[derive(Debug, Clone)]
struct LiquidityPenaltyHook {
    /// pool_id -> owner -> salt -> last_jit_block
    /// BUG: salt is part of penalty key, allowing split attacks
    jit_records: HashMap<u64, HashMap<([u8; 32], u64), u64>>,
    current_block: u64,
    penalty_blocks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PositionKey {
    pool_id: u64,
    owner: [u8; 32],
    salt: u64,
}

impl LiquidityPenaltyHook {
    fn new(penalty_blocks: u64) -> Self {
        Self {
            jit_records: HashMap::new(),
            current_block: 0,
            penalty_blocks,
        }
    }

    fn add_liquidity(
        &mut self,
        key: PositionKey,
        _amount: u128,
    ) -> Result<(), &'static str> {
        let penalty_key = (key.owner, key.salt);
        let pool_entry = self.jit_records.entry(key.pool_id).or_default();
        
        // VULNERABLE: Only checks penalty for exact (owner, salt) pair
        if let Some(last_block) = pool_entry.get(&penalty_key) {
            let blocks_since = self.current_block.saturating_sub(*last_block);
            if blocks_since < self.penalty_blocks {
                return Err("JIT penalty active for this salt");
            }
        }
        
        // Records JIT activity per (owner, salt) — NOT per owner
        pool_entry.insert(penalty_key, self.current_block);
        Ok(())
    }

    fn advance_block(&mut self) {
        self.current_block += 1;
    }
}

fn main() {
    let mut hook = LiquidityPenaltyHook::new(5);
    let owner = [1u8; 32];
    
    // First position with salt 0
    let pos0 = PositionKey { pool_id: 1, owner, salt: 0 };
    hook.add_liquidity(pos0, 1000).unwrap();
    hook.advance_block();
    
    // EXPLOIT: Same owner, different salt — bypasses penalty!
    let pos1 = PositionKey { pool_id: 1, owner, salt: 1 };
    let result = hook.add_liquidity(pos1, 500);
    assert!(result.is_ok(), "BUG: No penalty for different salt!");
    
    // Can repeat arbitrarily
    let pos2 = PositionKey { pool_id: 1, owner, salt: 2 };
    let result2 = hook.add_liquidity(pos2, 500);
    assert!(result2.is_ok(), "BUG: Still no penalty!");
    
    println!("Vulnerable fixture: penalty bypassed via salt splitting");
}