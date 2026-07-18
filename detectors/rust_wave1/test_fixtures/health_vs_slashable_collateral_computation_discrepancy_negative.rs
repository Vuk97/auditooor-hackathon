use std::collections::HashMap;
use alloy_primitives::U256;

/// Agent collateral position tracking
#[derive(Clone, Debug)]
struct CollateralPosition {
    asset: String,
    amount: U256,
    weight: u64, // weight in basis points (0-10000)
}

/// Agent state for liquidation decisions
#[derive(Clone, Debug)]
struct Agent {
    debt: U256,
    collaterals: Vec<CollateralPosition>,
}

impl Agent {
    /// Compute health factor using WEIGHTED collateral model
    /// This determines if agent is liquidatable
    fn health_factor(&self) -> U256 {
        let weighted_value = self.collaterals.iter().fold(U256::ZERO, |acc, c| {
            let weighted = c.amount * U256::from(c.weight) / U256::from(10000u64);
            acc + weighted
        });
        if self.debt.is_zero() {
            return U256::MAX;
        }
        weighted_value * U256::from(10000u64) / self.debt
    }

    /// Compute slashable collateral using SAME weighted model
    /// This determines how much can be seized to cover debt
    fn slashable_collateral(&self) -> U256 {
        // CORRECT: uses same weighted model as health_factor
        self.collaterals.iter().fold(U256::ZERO, |acc, c| {
            let weighted = c.amount * U256::from(c.weight) / U256::from(10000u64);
            acc + weighted
        })
    }

    fn is_healthy(&self, threshold: U256) -> bool {
        self.health_factor() >= threshold
    }

    fn can_cover_debt(&self) -> bool {
        self.slashable_collateral() >= self.debt
    }
}

fn main() {
    let agent = Agent {
        debt: U256::from(8000u64),
        collaterals: vec![
            CollateralPosition { asset: "ETH".into(), amount: U256::from(10000u64), weight: 8000 },
            CollateralPosition { asset: "BTC".into(), amount: U256::from(5000u64), weight: 5000 },
        ],
    };

    // Health: (10000*0.8 + 5000*0.5) = 8000+2500 = 10500 -> HF = 10500/8000 = 1.3125
    // Slashable: same 10500, can cover 8000 debt
    assert!(agent.is_healthy(U256::from(10000u64)));
    assert!(agent.can_cover_debt());
    println!("Agent healthy and slashable collateral sufficient");
}