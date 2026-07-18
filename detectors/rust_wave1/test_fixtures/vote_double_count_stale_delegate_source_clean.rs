use std::collections::HashMap;

pub type AccountId = u64;

pub struct VoteBook {
    delegate_of: HashMap<AccountId, AccountId>,
    voting_power_by_delegate: HashMap<AccountId, u64>,
    balances: HashMap<AccountId, u64>,
}

impl VoteBook {
    pub fn redelegate(&mut self, voter: AccountId, new_delegate: AccountId) {
        let current_delegate = self.delegate_of.get(&voter).copied();
        let votes = *self.balances.get(&voter).unwrap_or(&0);

        if let Some(old_delegate) = current_delegate {
            self.voting_power_by_delegate
                .entry(old_delegate)
                .and_modify(|power| *power = power.saturating_sub(votes));
        }

        self.delegate_of.insert(voter, new_delegate);

        self.voting_power_by_delegate
            .entry(new_delegate)
            .and_modify(|power| *power += votes)
            .or_insert(votes);
    }
}
