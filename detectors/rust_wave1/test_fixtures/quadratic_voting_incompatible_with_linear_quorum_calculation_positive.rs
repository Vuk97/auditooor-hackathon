use std::marker::PhantomData;

/// QuadraticVoteStrategy - uses square root of voting power
pub struct QuadraticVoteStrategy;

impl QuadraticVoteStrategy {
    pub fn compute_votes(voting_power: u64) -> u64 {
        // Properly scaled integer square root
        let mut x = voting_power;
        let mut y = (x + 1) / 2;
        while y < x {
            x = y;
            y = (x + voting_power / x) / 2;
        }
        x
    }
}

/// GovernorVotesQuorumFraction - uses LINEAR vote counting for quorum (BUG!)
pub struct GovernorVotesQuorumFraction<T> {
    quorum_numerator: u64,
    quorum_denominator: u64,
    _marker: PhantomData<T>,
}

impl<T> GovernorVotesQuorumFraction<T> {
    pub fn new(quorum_numerator: u64, quorum_denominator: u64) -> Self {
        Self {
            quorum_numerator,
            quorum_denominator,
            _marker: PhantomData,
        }
    }

    /// BUG: quorum computed in LINEAR space while votes are in QUADRATIC space
    pub fn quorum(&self, total_voting_power: u64) -> u64 {
        // Linear calculation: e.g., 4% of total supply
        (total_voting_power * self.quorum_numerator) / self.quorum_denominator
    }

    pub fn quorum_reached(&self, total_voting_power: u64, votes_cast: u64) -> bool {
        // Votes are quadratic (sqrt-weighted), but quorum is linear
        // This causes mismatch: quadratic votes are much smaller than linear quorum
        let linear_quorum = self.quorum(total_voting_power);
        
        // BUG: comparing quadratic votes against linear threshold!
        // QuadraticVoteStrategy::compute_votes(votes_cast) is sqrt(votes_cast)
        // but linear_quorum is ~0.04 * total_voting_power (linear)
        // For large token holders, sqrt(votes) << linear threshold -> quorum never reached
        // For small token holders, sqrt(votes) > linear threshold -> quorum trivially reached
        let quadratic_votes = QuadraticVoteStrategy::compute_votes(votes_cast);
        quadratic_votes >= linear_quorum
    }
}

/// LucidGovernor - combines quadratic voting with linear quorum (VULNERABLE)
pub struct LucidGovernor {
    vote_strategy: QuadraticVoteStrategy,
    quorum_fraction: GovernorVotesQuorumFraction<QuadraticVoteStrategy>,
}

impl LucidGovernor {
    pub fn new() -> Self {
        Self {
            vote_strategy: QuadraticVoteStrategy,
            quorum_fraction: GovernorVotesQuorumFraction::new(4, 100), // 4% quorum
        }
    }

    pub fn cast_vote(&self, voter_power: u64) -> u64 {
        QuadraticVoteStrategy::compute_votes(voter_power)
    }

    pub fn check_quorum(&self, total_supply: u64, total_votes_cast: u64) -> bool {
        // VULNERABLE: quadratic votes checked against linear quorum threshold
        self.quorum_fraction.quorum_reached(total_supply, total_votes_cast)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_never_reached_bug() {
        let gov = LucidGovernor::new();
        // 1M tokens total, 4% quorum = 40K linear
        // But sqrt(500K votes) = ~707 quadratic, which is << 40K linear
        // Quorum impossible to reach!
        let result = gov.check_quorum(1_000_000, 500_000);
        assert!(!result); // BUG: should be reachable with 50% participation
    }

    #[test]
    fn test_quorum_trivially_reached_bug() {
        let gov = LucidGovernor::new();
        // Small supply: 100 total, 4 quorum linear
        // sqrt(50) = 7 quadratic, which is > 4? No, but with 100 votes: sqrt(100)=10 > 4
        // Actually demonstrates asymmetric behavior
        let result = gov.check_quorum(100, 100);
        assert!(result); // May be trivially true in small cases
    }
}