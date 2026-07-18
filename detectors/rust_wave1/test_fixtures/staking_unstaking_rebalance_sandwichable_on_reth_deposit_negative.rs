use std::collections::HashMap;

/// Simulates a staking vault with proper slippage protection on LST deposits
pub struct StakingVault {
    pub total_supply: u128,
    pub weights: HashMap<u8, u16>, // asset_id -> weight in basis points
    pub balances: HashMap<u8, u128>,
}

/// Price oracle with slippage check
pub trait PriceOracle {
    fn get_rate(&self, asset_id: u8) -> u128;
    fn get_rate_with_slippage(&self, asset_id: u8, max_slippage_bps: u16) -> Option<u128>;
}

impl StakingVault {
    pub fn new() -> Self {
        Self {
            total_supply: 0,
            weights: HashMap::new(),
            balances: HashMap::new(),
        }
    }

    /// Clean: stake with slippage-gated deposit into rETH (asset_id = 1)
    pub fn stake(
        &mut self,
        eth_amount: u128,
        oracle: &dyn PriceOracle,
        min_out: u128, // explicit slippage gate
    ) -> u128 {
        let reth_rate = oracle.get_rate_with_slippage(1, 50).expect("stale oracle");
        let reth_out = eth_amount * reth_rate / 1e18 as u128;
        
        // Slippage gate: revert if output below user-specified minimum
        assert!(reth_out >= min_out, "slippage exceeded");
        
        let mint_amount = self.calculate_mint_amount(eth_amount);
        self.total_supply += mint_amount;
        *self.balances.entry(1).or_insert(0) += reth_out;
        
        mint_amount
    }

    /// Clean: rebalance with slippage protection
    pub fn rebalance_to_weight(
        &mut self,
        asset_id: u8,
        oracle: &dyn PriceOracle,
        min_out: u128,
    ) {
        let current = self.balances.get(&asset_id).copied().unwrap_or(0);
        let target = self.calculate_target(asset_id);
        
        if target > current {
            let deposit = target - current;
            let rate = oracle.get_rate_with_slippage(asset_id, 50).expect("stale oracle");
            let out = deposit * rate / 1e18 as u128;
            assert!(out >= min_out, "rebalance slippage exceeded");
            *self.balances.entry(asset_id).or_insert(0) += out;
        }
    }

    fn calculate_mint_amount(&self, _eth_in: u128) -> u128 {
        if self.total_supply == 0 { 1000 } else { 500 }
    }

    fn calculate_target(&self, asset_id: u8) -> u128 {
        let weight = self.weights.get(&asset_id).copied().unwrap_or(5000);
        self.total_supply * weight as u128 / 10000
    }
}
