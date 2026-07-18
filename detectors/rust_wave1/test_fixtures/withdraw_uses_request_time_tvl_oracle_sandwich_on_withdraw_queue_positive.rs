use std::collections::VecDeque;

#[derive(Clone, Debug)]
struct WithdrawRequest {
    user: [u8; 32],
    shares: u128,
    // VULNERABLE: No epoch tracking, stores computed amount at request time
    computed_amount: u128,
}

struct WithdrawQueue {
    requests: VecDeque<WithdrawRequest>,
    total_shares: u128,
    current_tvl: u128,
    oracle_price: u128,
}

impl WithdrawQueue {
    fn new() -> Self {
        Self {
            requests: VecDeque::new(),
            total_shares: 0,
            current_tvl: 1_000_000,
            oracle_price: 1_000_000,
        }
    }

    // VULNERABLE: Computes amount at request time using current TVL + oracle
    fn request_withdraw(&mut self, user: [u8; 32], shares: u128) -> u128 {
        // BUG: Uses request-time TVL and oracle price, not claim-time
        let tvl_per_share = self.current_tvl / self.total_shares.max(1);
        let oracle_adjusted_tvl = tvl_per_share * self.oracle_price / 1_000_000;
        let computed_amount = shares * oracle_adjusted_tvl;
        
        self.requests.push_back(WithdrawRequest {
            user,
            shares,
            computed_amount,
        });
        self.total_shares += shares;
        computed_amount
    }

    fn update_tvl(&mut self, new_tvl: u128) {
        self.current_tvl = new_tvl;
    }

    fn update_oracle(&mut self, new_price: u128) {
        self.oracle_price = new_price;
    }

    // VULNERABLE: Claims pre-computed amount, no re-computation at claim time
    fn claim_withdraw(&mut self, user: [u8; 32]) -> Option<u128> {
        let pos = self.requests.iter().position(|r| r.user == user)?;
        let req = self.requests.remove(pos)?;
        // Returns amount computed at request time, vulnerable to sandwich
        Some(req.computed_amount)
    }
}

fn main() {
    let mut queue = WithdrawQueue::new();
    
    let user = [1u8; 32];
    
    // Attacker manipulates oracle/TVL upward
    queue.update_oracle(1_100_000);
    queue.update_tvl(1_100_000);
    
    // Victim requests withdraw at inflated TVL
    let promised = queue.request_withdraw(user, 100);
    println!("Promised: {}", promised);
    
    // Attacker restores oracle/TVL
    queue.update_oracle(1_000_000);
    queue.update_tvl(1_000_000);
    
    // Protocol pays out inflated amount, extracting value from other users
    let claimed = queue.claim_withdraw(user).unwrap();
    println!("Claimed: {}", claimed);
}