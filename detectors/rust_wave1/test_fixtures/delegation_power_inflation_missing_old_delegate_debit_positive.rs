use std::collections::HashMap;

pub struct Governance {
    pub delegations: HashMap<u64, u64>,
    pub delegation_power: HashMap<u64, u128>,
    pub balances: HashMap<u64, u128>,
}

impl Governance {
    pub fn delegate(&mut self, delegator: u64, new_delegate: u64) {
        let old_delegate = self.delegations.get(&delegator).copied();
        let amount = *self.balances.get(&delegator).unwrap_or(&0);

        if old_delegate == Some(new_delegate) {
            return;
        }

        self.delegations.insert(delegator, new_delegate);
        self.delegation_power
            .entry(new_delegate)
            .and_modify(|power| *power += amount)
            .or_insert(amount);
    }
}
