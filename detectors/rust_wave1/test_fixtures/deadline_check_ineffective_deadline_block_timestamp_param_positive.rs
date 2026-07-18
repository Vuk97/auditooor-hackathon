use std::time::{SystemTime, UNIX_EPOCH};

/// A swap router that incorrectly uses block.timestamp as deadline parameter.
/// This makes the deadline check always pass, allowing outdated transactions.
pub struct SwapRouter;

impl SwapRouter {
    pub fn get_block_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub fn swap_exact_tokens_for_tokens(
        &self,
        amount_in: u64,
        min_out: u64,
        path: Vec<u64>,
        _user_deadline: u64, // User-supplied deadline is ignored!
    ) -> Result<u64, &'static str> {
        let block_timestamp = self.get_block_timestamp();
        
        // BUG: Using block.timestamp as the deadline parameter makes check always pass
        // since block_timestamp == block_timestamp is always true (or we pass it to
        // an external call that compares against the same block.timestamp).
        let deadline = block_timestamp; // Ineffective: deadline is always current block time
        
        // This check is meaningless - deadline equals current time, so it's always "valid"
        if deadline < block_timestamp {
            return Err("Transaction expired"); // Never triggers
        }
        
        // In real buggy code, this would call e.g. curve_pool.exchange_underlying(
        //     ..., block_timestamp as i64, ...)
        // where the AMM compares deadline >= block.timestamp, which is always true
        
        // Execute swap logic (simplified)
        let out = amount_in * path[0] / min_out.max(1);
        Ok(out)
    }
}

fn main() {
    let router = SwapRouter;
    // Even with an expired deadline, transaction succeeds
    let expired_deadline = 1; // Long expired
    
    let result = router.swap_exact_tokens_for_tokens(1000, 900, vec![2], expired_deadline);
    assert!(result.is_ok()); // BUG: Should have failed but passes!
}