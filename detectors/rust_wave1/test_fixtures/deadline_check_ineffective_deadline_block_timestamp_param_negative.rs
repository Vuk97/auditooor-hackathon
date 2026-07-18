use std::time::{SystemTime, UNIX_EPOCH};

/// A swap router that properly validates deadlines against a user-supplied value.
pub struct SwapRouter;

impl SwapRouter {
    pub fn swap_exact_tokens_for_tokens(
        &self,
        amount_in: u64,
        min_out: u64,
        path: Vec<u64>,
        deadline: u64,
    ) -> Result<u64, &'static str> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Proper deadline check: user-supplied deadline must be in the future
        if deadline < now {
            return Err("Transaction expired");
        }
        
        // Execute swap logic (simplified)
        let out = amount_in * path[0] / min_out.max(1);
        Ok(out)
    }
}

fn main() {
    let router = SwapRouter;
    // User provides a future deadline (e.g., 1 hour from now)
    let future_deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() + 3600;
    
    let result = router.swap_exact_tokens_for_tokens(1000, 900, vec![2], future_deadline);
    assert!(result.is_ok());
}