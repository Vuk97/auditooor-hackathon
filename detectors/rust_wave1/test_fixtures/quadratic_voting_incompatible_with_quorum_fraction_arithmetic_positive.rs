use std::collections::BTreeMap;

/// Quadratic voting with INCOMPATIBLE quorum: sqrt(votes) vs linear totalSupply.
pub struct QuadraticGovernor {
    pub total_supply: u64,
    pub quorum_numerator: u64,
    pub quorum_denominator: u64,
}

impl QuadraticGovernor {
    pub fn new(total_supply: u64) -> Self {
        Self {
            total_supply,
            quorum_numerator: 4,    // 4%
            quorum_denominator: 100,
        }
    }

    /// Quadratic vote counting: returns sqrt(votes), much smaller than raw votes.
    pub fn count_votes(&self, votes: u64) -> u64 {
        integer_sqrt(votes)
    }

    /// BUG: Quorum computed from total_supply in ORIGINAL units, not sqrt units.
    /// total_supply is ~1M, quorum is ~40k, but sqrt(1M votes) = 1k max.
    /// Quorum is mathematically unreachable with quadratic votes.
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

fn integer_sqrt(n: u64) -> u64 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quadratic_quorum_unreachable() {
        let gov = QuadraticGovernor::new(1_000_000);
        let quorum = gov.quorum();
        assert_eq!(quorum, 40_000);
        // Even with ALL tokens voted, sqrt(1_000_000) = 1_000 << 40_000
        let max_possible_votes = gov.count_votes(1_000_000);
        assert_eq!(max_possible_votes, 1_000);
        assert!(!gov.has_reached_quorum(1_000_000)); // BUG: unreachable quorum!
    }
}