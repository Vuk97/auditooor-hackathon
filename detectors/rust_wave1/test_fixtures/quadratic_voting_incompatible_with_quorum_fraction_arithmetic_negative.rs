use std::collections::BTreeMap;

/// Linear voting with standard quorum: votes and total supply use same units.
pub struct LinearGovernor {
    pub total_supply: u64,
    pub quorum_numerator: u64,
    pub quorum_denominator: u64,
}

impl LinearGovernor {
    pub fn new(total_supply: u64) -> Self {
        Self {
            total_supply,
            quorum_numerator: 4,    // 4%
            quorum_denominator: 100,
        }
    }

    /// Standard linear vote counting.
    pub fn count_votes(&self, votes: u64) -> u64 {
        votes
    }

    /// Quorum computed from total_supply in same units as votes.
    pub fn quorum(&self) -> u64 {
        self.total_supply
            .checked_mul(self.quorum_numerator)
            .and_then(|v| v.checked_div(self.quorum_denominator))
            .unwrap_or(0)
    }

    pub fn has_reached_quorum(&self, cast_votes: u64) -> bool {
        self.count_votes(cast_votes) >= self.quorum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_quorum_reachable() {
        let gov = LinearGovernor::new(1_000_000);
        let quorum = gov.quorum();
        assert_eq!(quorum, 40_000);
        // With 50k votes, quorum is reachable
        assert!(gov.has_reached_quorum(50_000));
    }
}