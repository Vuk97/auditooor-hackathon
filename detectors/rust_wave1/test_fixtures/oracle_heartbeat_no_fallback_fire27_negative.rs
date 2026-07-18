pub struct FeedRound {
    pub answer: u128,
    pub updated_at: u64,
}

pub struct Position {
    pub collateral: u128,
    pub debt: u128,
}

pub enum OracleError {
    StalePrice,
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
    ) -> Result<u128, OracleError> {
        let price = round.answer;
        let oracle_age = now.saturating_sub(round.updated_at);
        if oracle_age > self.max_heartbeat {
            return Err(OracleError::StalePrice);
        }

        let collateral_value = position.collateral.saturating_mul(price) / 1_000_000;
        Ok(position.debt.saturating_sub(collateral_value))
    }
}
