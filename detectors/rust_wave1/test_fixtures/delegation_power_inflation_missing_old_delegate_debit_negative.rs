use std::collections::HashMap;

pub struct SafeGovernance {
    pub delegations: HashMap<u64, u64>,
    pub delegation_power: HashMap<u64, u128>,
    pub balances: HashMap<u64, u128>,
}

impl SafeGovernance {
    pub fn delegate(&mut self, delegator: u64, new_delegate: u64) {
        let previous_delegate = self.delegations.get(&delegator).copied();
        let amount = *self.balances.get(&delegator).unwrap_or(&0);

        if previous_delegate == Some(new_delegate) {
            return;
        }

        if let Some(previous_delegate) = previous_delegate {
            self.delegation_power
                .entry(previous_delegate)
                .and_modify(|power| *power = power.saturating_sub(amount));
        }

        self.delegations.insert(delegator, new_delegate);
        self.delegation_power
            .entry(new_delegate)
            .and_modify(|power| *power += amount)
            .or_insert(amount);
    }
}
