use std::collections::HashMap;

struct NftInfo {
    total_power_in_tokens: u64,
    user_power: HashMap<u64, u64>,
}

struct UserKeeper {
    nft_info: NftInfo,
}

impl UserKeeper {
    fn new() -> Self {
        Self {
            nft_info: NftInfo {
                total_power_in_tokens: 0,
                user_power: HashMap::new(),
            },
        }
    }

    fn register_nft(&mut self, token_id: u64, power: u64) {
        self.nft_info.user_power.insert(token_id, power);
        self.nft_info.total_power_in_tokens += power;
    }

    fn transfer_nft(&mut self, from: u64, to: u64) {
        if let Some(power) = self.nft_info.user_power.remove(&from) {
            self.nft_info.user_power.insert(to, power);
        }
    }

    fn burn_nft(&mut self, token_id: u64) {
        self.nft_info.user_power.remove(&token_id);
    }

    fn get_total_vote_weight(&self) -> u64 {
        self.nft_info.total_power_in_tokens
    }

    fn get_user_vote_weight(&self, token_id: u64) -> u64 {
        *self.nft_info.user_power.get(&token_id).unwrap_or(&0)
    }
}

struct GovernancePool {
    user_keeper: UserKeeper,
    proposals: HashMap<u64, u64>,
}

impl GovernancePool {
    fn new() -> Self {
        Self {
            user_keeper: UserKeeper::new(),
            proposals: HashMap::new(),
        }
    }

    fn quorum_reached(&self, proposal_id: u64, votes_for: u64) -> bool {
        let total_weight = self.user_keeper.get_total_vote_weight();
        let threshold = self.proposals.get(&proposal_id).copied().unwrap_or(0);
        if total_weight == 0 {
            return false;
        }
        votes_for * 100 >= total_weight * threshold
    }
}

fn main() {
    let mut gov = GovernancePool::new();
    gov.user_keeper.register_nft(1, 100);
    gov.user_keeper.register_nft(2, 200);
    gov.proposals.insert(1, 51);
    assert!(gov.quorum_reached(1, 153));
    gov.user_keeper.burn_nft(2);
    assert!(!gov.quorum_reached(1, 153));
    let total = gov.user_keeper.get_total_vote_weight();
    let active: u64 = gov.user_keeper.nft_info.user_power.values().sum();
    println!("total_power_in_tokens={}, active_power={}", total, active);
    assert_eq!(total, 300);
    assert_eq!(active, 100);
}