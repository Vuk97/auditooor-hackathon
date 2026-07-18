use std::collections::HashMap;

pub struct ConvictionScore {
    is_governance: HashMap<u64, bool>,
    scores: HashMap<u64, u64>,
    total_conviction: u64,
}

impl ConvictionScore {
    pub fn new() -> Self {
        Self {
            is_governance: HashMap::new(),
            scores: HashMap::new(),
            total_conviction: 0,
        }
    }

    pub fn get_prior_conviction_score(&self, user: u64, _block: u64) -> u64 {
        *self.scores.get(&user).unwrap_or(&0)
    }

    pub fn update_conviction_score(&mut self, user: u64, current_block: u64) {
        let prior_score = self.get_prior_conviction_score(user, current_block.saturating_sub(1));
        
        // CORRECT: compute delta BEFORE mutating state
        let was_governance = *self.is_governance.get(&user).unwrap_or(&false);
        let delta = if was_governance { prior_score } else { 0 };
        
        // Now mutate state
        self.is_governance.insert(user, false);
        
        // Update total conviction with correct delta
        self.total_conviction = self.total_conviction.saturating_sub(delta);
        
        // Set new score based on current state
        let new_score = self.calculate_new_score(user);
        self.scores.insert(user, new_score);
    }

    fn calculate_new_score(&self, user: u64) -> u64 {
        // Simplified scoring logic
        if *self.is_governance.get(&user).unwrap_or(&false) {
            100
        } else {
            0
        }
    }
}

fn main() {
    let mut cs = ConvictionScore::new();
    cs.is_governance.insert(1, true);
    cs.scores.insert(1, 100);
    cs.total_conviction = 100;
    cs.update_conviction_score(1, 10);
}