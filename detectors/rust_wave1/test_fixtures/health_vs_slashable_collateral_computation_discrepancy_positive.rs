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

    /// Compute slashable collateral using RAW (unweighted) model
    /// BUG: different model than health_factor — can cause bad debt
    fn slashable_collateral(&self) -> U256 {
        // VULNERABLE: uses raw sum, ignoring weights
        self.collaterals.iter().fold(U256::ZERO, |acc, c| {
            acc + c.amount // RAW: no weight applied!
        })
    }

    fn is_healthy(&self, threshold: U256) -> bool {
        self.health_factor() >= threshold
    }

    fn can_cover_debt(&self) -> bool {
        self.slashable_collateral() >= self.debt
    }

    /// Liquidation entry point — may seize insufficient collateral
    fn liquidate(&self) -> U256 {
        if self.is_healthy(U256::from(10000u64)) {
            return U256::ZERO;
        }
        let slashable = self.slashable_collateral();
        // BUG: slashable may be > debt in raw terms, but health check
        // may fail due to weighted calculation. Conversely, health may
        // indicate liquidatable but weighted slashable < debt.
        // Here we demonstrate: health uses weighted, slashable uses raw.
        if slashable < self.debt {
            // Protocol absorbs bad debt — funds cannot cover!
            println!("BAD DEBT: slashable {} < debt {} despite health check", slashable, self.debt);
        }
        slashable.min(self.debt)
    }
}

fn main() {
    // Scenario: collateral has low weights, so weighted value < raw value
    let agent = Agent {
        debt: U256::from(9000u64),
        collaterals: vec![
            // Weighted: 10000 * 0.5 = 5000, Raw: 10000
            CollateralPosition { asset: "ETH".into(), amount: U256::from(10000u64), weight: 5000 },
            // Weighted: 5000 * 0.4 = 2000, Raw: 5000
            CollateralPosition { asset: "BTC".into(), amount: U256::from(5000u64), weight: 4000 },
        ],
    };

    // Health: 5000 + 2000 = 7000, HF = 7000/9000 = 0.777 < 1.0 -> UNHEALTHY
    // But slashable (raw): 10000 + 5000 = 15000 > 9000 -> seems coverable
    // 
    // INVERSE BUG: If we flip: high debt, health barely passes but weighted slashable < debt:
    // Actually demonstrate the core discrepancy: health uses weighted, slashable uses raw
    println!("Health factor: {:?}", agent.health_factor());
    println!("Slashable (raw): {:?}", agent.slashable_collateral());
    
    // The real bug: if collateral weights are low, health says unhealthy,
    // but raw slashable seems fine. Or: health barely passes, but weighted
    // collateral insufficient to cover.
    let _ = agent.liquidate();

    // Better demonstration: agent with weights making health < threshold
    // but raw slashable > debt (false confidence), OR:
    // health check uses weighted, liquidation uses raw → mismatch
    let risky = Agent {
        debt: U256::from(12000u64),
        collaterals: vec![
            CollateralPosition { asset: "ETH".into(), amount: U256::from(15000u64), weight: 8000 },
            CollateralPosition { asset: "BTC".into(), amount: U256::from(10000u64), weight: 0 }, // worthless in health!
        ],
    };
    // Health: 15000*0.8 + 0 = 12000, HF = 12000/12000 = 1.0 (borderline)
    // Slashable raw: 25000 > 12000 — but weighted slashable would be only 12000
    // If weight changes slightly, health fails but raw still seems OK
    println!("Risky health: {:?}", risky.health_factor());
    println!("Risky slashable raw: {:?}", risky.slashable_collateral());
    let _ = risky.liquidate();
}