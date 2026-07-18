use std::collections::HashMap;

pub struct BoostController {
    delegations: HashMap<u64, u64>, // user_id -> pool_id
    owner: u64,
}

impl BoostController {
    pub fn new(owner: u64) -> Self {
        Self {
            delegations: HashMap::new(),
            owner,
        }
    }

    /// Only the owner or the user themselves can update delegation
    pub fn update_user_boost(&mut self, caller: u64, user_id: u64, pool_id: u64) -> Result<(), &'static str> {
        // Access control: only owner or self-delegation allowed
        if caller != self.owner && caller != user_id {
            return Err("unauthorized: only owner or user can update delegation");
        }
        self.delegations.insert(user_id, pool_id);
        Ok(())
    }

    pub fn get_delegation(&self, user_id: u64) -> Option<u64> {
        self.delegations.get(&user_id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorized_update() {
        let mut ctrl = BoostController::new(1);
        assert!(ctrl.update_user_boost(1, 2, 100).is_ok()); // owner sets for user 2
        assert_eq!(ctrl.get_delegation(2), Some(100));
    }

    #[test]
    fn test_self_update() {
        let mut ctrl = BoostController::new(1);
        assert!(ctrl.update_user_boost(2, 2, 100).is_ok()); // user 2 self-delegates
        assert_eq!(ctrl.get_delegation(2), Some(100));
    }

    #[test]
    fn test_unauthorized_blocked() {
        let mut ctrl = BoostController::new(1);
        assert!(ctrl.update_user_boost(3, 2, 0).is_err()); // attacker cannot DoS user 2
    }
}