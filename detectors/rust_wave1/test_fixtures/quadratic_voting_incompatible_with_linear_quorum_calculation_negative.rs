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

/// QuorumCalculator - uses SAME quadratic vote counting for quorum
pub struct QuadraticQuorumCalculator<T> {
    quorum_threshold: u64,
    _marker: PhantomData<T>,
}

impl<T> QuadraticQuorumCalculator<T> {
    pub fn new(quorum_threshold: u64) -> Self {
        Self {
            quorum_threshold,
            _marker: PhantomData,
        }
    }

    pub fn quorum_reached(&self, total_voting_power: u64, votes_cast: u64) -> bool {
        // CORRECT: quorum computed in same quadratic space as votes
        let quadratic_total = QuadraticVoteStrategy::compute_votes(total_voting_power);
        let quadratic_votes = QuadraticVoteStrategy::compute_votes(votes_cast);
        
        // Quorum threshold is also in quadratic space
        quadratic_votes >= self.quorum_threshold && quadratic_votes * 100 >= quadratic_total * 51
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quadratic_consistency() {
        let calc = QuadraticQuorumCalculator::<QuadraticVoteStrategy>::new(100);
        // 10000 linear power -> 100 quadratic, need 51% of quadratic total
        assert!(calc.quorum_reached(10000, 5100)); // sqrt(5100) ~ 71, sqrt(10000) = 100, 71 >= 51
    }
}