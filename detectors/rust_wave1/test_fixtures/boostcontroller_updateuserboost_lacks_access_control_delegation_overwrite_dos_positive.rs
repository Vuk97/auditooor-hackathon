use std::collections::HashMap;

pub struct BoostController {
    delegations: HashMap<u64, u64>, // user_id -> pool_id
}

impl BoostController {
    pub fn new() -> Self {
        Self {
            delegations: HashMap::new(),
        }
    }

    /// NO ACCESS CONTROL: anyone can call this to overwrite any user's delegation
    pub fn update_user_boost(&mut self, user_id: u64, pool_id: u64) {
        // Missing authorization check - attacker can pass pool_id=0 to DoS victim
        self.delegations.insert(user_id, pool_id);
    }

    pub fn get_delegation(&self, user_id: u64) -> Option<u64> {
        self.delegations.get(&user_id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exploit_dos() {
        let mut ctrl = BoostController::new();
        
        // Victim legitimately delegates to pool 100
        ctrl.update_user_boost(1, 100);
        assert_eq!(ctrl.get_delegation(1), Some(100));
        
        // Attacker (any caller) overwrites victim's delegation to pool 0 (DoS)
        ctrl.update_user_boost(1, 0);
        assert_eq!(ctrl.get_delegation(1), Some(0)); // victim's voting power broken
    }
}