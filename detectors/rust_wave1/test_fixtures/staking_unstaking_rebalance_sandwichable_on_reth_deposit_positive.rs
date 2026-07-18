use std::collections::HashMap;

/// Vulnerable: staking vault with NO slippage protection on internal LST deposits
/// MEV attacker can sandwich the internal rETH deposit to steal value from stakers
pub struct StakingVault {
    pub total_supply: u128,
    pub weights: HashMap<u8, u16>,
    pub balances: HashMap<u8, u128>,
}

/// Price oracle WITHOUT slippage check
pub trait PriceOracle {
    fn get_rate(&self, asset_id: u8) -> u128;
}

impl StakingVault {
    pub fn new() -> Self {
        Self {
            total_supply: 0,
            weights: HashMap::new(),
            balances: HashMap::new(),
        }
    }

    /// VULNERABLE: stake with UNCHECKED internal deposit into rETH
    /// No min_out parameter, no slippage check on the internal rETH deposit
    pub fn stake(&mut self, eth_amount: u128, oracle: &dyn PriceOracle) -> u128 {
        // Direct rate query with no staleness/slippage validation
        let reth_rate = oracle.get_rate(1);
        let reth_out = eth_amount * reth_rate / 1e18 as u128;
        
        // NO slippage gate here! Attacker manipulates pool before this call
        
        let mint_amount = self.calculate_mint_amount(eth_amount);
        self.total_supply += mint_amount;
        *self.balances.entry(1).or_insert(0) += reth_out;
        
        mint_amount
    }

    /// VULNERABLE: unstake with UNCHECKED internal rETH->ETH conversion
    pub fn unstake(&mut self, safeth_amount: u128, oracle: &dyn PriceOracle) -> u128 {
        let eth_owed = self.calculate_eth_owed(safeth_amount);
        
        // Direct rate with no slippage check on rETH withdrawal
        let reth_rate = oracle.get_rate(1);
        let reth_needed = eth_owed * 1e18 as u128 / reth_rate;
        
        *self.balances.get_mut(&1).unwrap() -= reth_needed;
        self.total_supply -= safeth_amount;
        
        eth_owed
    }

    /// VULNERABLE: rebalance with UNCHECKED deposit
    pub fn rebalance_to_weight(&mut self, asset_id: u8, oracle: &dyn PriceOracle) {
        let current = self.balances.get(&asset_id).copied().unwrap_or(0);
        let target = self.calculate_target(asset_id);
        
        if target > current {
            let deposit = target - current;
            // No slippage protection on internal deposit
            let rate = oracle.get_rate(asset_id);
            let out = deposit * rate / 1e18 as u128;
            // NO assert!(out >= min_out) — sandwichable!
            *self.balances.entry(asset_id).or_insert(0) += out;
        }
    }

    fn calculate_mint_amount(&self, _eth_in: u128) -> u128 {
        if self.total_supply == 0 { 1000 } else { 500 }
    }

    fn calculate_eth_owed(&self, safeth_amount: u128) -> u128 {
        safeth_amount * self.total_supply / 10000 // simplified
    }

    fn calculate_target(&self, asset_id: u8) -> u128 {
        let weight = self.weights.get(&asset_id).copied().unwrap_or(5000);
        self.total_supply * weight as u128 / 10000
    }
}
