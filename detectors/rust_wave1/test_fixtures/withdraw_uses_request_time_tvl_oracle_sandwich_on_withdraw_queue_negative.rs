use std::collections::VecDeque;

#[derive(Clone, Debug)]
struct WithdrawRequest {
    user: [u8; 32],
    shares: u128,
    claim_epoch: u64,
}

struct WithdrawQueue {
    requests: VecDeque<WithdrawRequest>,
    total_shares: u128,
    epochs: Vec<EpochState>,
}

#[derive(Clone, Debug)]
struct EpochState {
    tvl: u128,
    total_shares: u128,
}

impl WithdrawQueue {
    fn new() -> Self {
        Self {
            requests: VecDeque::new(),
            total_shares: 0,
            epochs: vec![EpochState { tvl: 0, total_shares: 0 }],
        }
    }

    fn request_withdraw(&mut self, user: [u8; 32], shares: u128) -> u64 {
        let claim_epoch = self.epochs.len() as u64;
        self.requests.push_back(WithdrawRequest {
            user,
            shares,
            claim_epoch,
        });
        self.total_shares += shares;
        claim_epoch
    }

    fn finalize_epoch(&mut self, tvl: u128) {
        let total_shares = self.total_shares;
        self.epochs.push(EpochState { tvl, total_shares });
    }

    fn claim_withdraw(&mut self, request: &WithdrawRequest) -> u128 {
        let epoch = &self.epochs[request.claim_epoch as usize];
        if epoch.total_shares == 0 {
            return 0;
        }
        // FIXED: Use claim-epoch TVL, not request-time TVL
        let amount = request.shares * epoch.tvl / epoch.total_shares;
        amount
    }
}

fn main() {
    let mut queue = WithdrawQueue::new();
    queue.finalize_epoch(1_000_000);
    
    let user = [1u8; 32];
    queue.request_withdraw(user, 100);
    
    // TVL changes before claim
    queue.finalize_epoch(1_100_000);
    
    let req = queue.requests.front().unwrap().clone();
    let amount = queue.claim_withdraw(&req);
    println!("Claimed: {}", amount);
}