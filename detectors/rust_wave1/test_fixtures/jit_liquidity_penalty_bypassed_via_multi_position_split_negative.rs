use std::collections::HashMap;

/// Tracks JIT liquidity penalties per pool + owner + salt combination.
/// Clean version: penalty is enforced across ALL positions for an owner
/// in a pool, regardless of salt splits.
#[derive(Debug, Clone)]
struct LiquidityPenaltyHook {
    /// pool_id -> owner -> last_jit_block -> penalty_applied
    jit_records: HashMap<u64, HashMap<[u8; 32], u64>>,
    current_block: u64,
    penalty_blocks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PositionKey {
    pool_id: u64,
    owner: [u8; 32],
    // salt is part of position identity but NOT penalty tracking
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
        let owner_key = key.owner;
        let pool_entry = self.jit_records.entry(key.pool_id).or_default();
        
        // CRITICAL FIX: Check penalty across ALL salts for this owner+pool
        if let Some(last_block) = pool_entry.get(&owner_key) {
            let blocks_since = self.current_block.saturating_sub(*last_block);
            if blocks_since < self.penalty_blocks {
                return Err("JIT penalty active: recent liquidity addition detected for this owner");
            }
        }
        
        // Record JIT activity for owner (not per-salt)
        pool_entry.insert(owner_key, self.current_block);
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
    
    // Attempt second position with DIFFERENT salt — should STILL be penalized
    let pos1 = PositionKey { pool_id: 1, owner, salt: 1 };
    let result = hook.add_liquidity(pos1, 500);
    assert!(result.is_err(), "Expected penalty for same owner regardless of salt");
    
    println!("Clean fixture: penalty correctly enforced across salts");
}