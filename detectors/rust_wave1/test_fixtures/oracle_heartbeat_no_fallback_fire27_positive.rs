pub struct FeedRound {
    pub answer: u128,
    pub updated_at: u64,
}

pub struct Position {
    pub collateral: u128,
    pub debt: u128,
}

pub struct LendingMarket {
    pub max_heartbeat: u64,
}

impl LendingMarket {
    pub fn liquidation_shortfall(
        &self,
        round: FeedRound,
        now: u64,
        position: Position,
    ) -> u128 {
        let price = round.answer;
        let oracle_age = now.saturating_sub(round.updated_at);
        let heartbeat_limit = self.max_heartbeat;
        let _staleness_context = oracle_age.saturating_add(heartbeat_limit);

        // BUG: the heartbeat age is never compared before value math.
        let collateral_value = position.collateral.saturating_mul(price) / 1_000_000;
        position.debt.saturating_sub(collateral_value)
    }
}
