use std::collections::HashMap;

pub struct UserConfiguration {
    pub data: u128,
}

impl UserConfiguration {
    pub fn set_reserve_flag(&mut self, reserve_id: u8, enabled: bool) {
        if reserve_id >= 64 {
            return;
        }
        let shift = (reserve_id as u32) * 2;
        let mask = 1u128 << shift;
        if enabled {
            self.data |= mask;
        } else {
            self.data &= !mask;
        }
    }
}

pub struct LendingVault {
    pub total_collateral: u128,
    pub total_shares: u128,
    pub collateral_balances: Vec<(u64, u128)>,
}

impl LendingVault {
    pub fn redeem_mul_before_div(&mut self, user: u64, shares: u128) -> u128 {
        let collateral_payout = shares
            .checked_mul(self.total_collateral)
            .expect("collateral overflow")
            .checked_div(self.total_shares)
            .expect("nonzero share supply");
        self.total_collateral -= collateral_payout;
        self.total_shares -= shares;
        self.collateral_balances.push((user, collateral_payout));
        collateral_payout
    }
}

pub struct PositionVault {
    pub positions: HashMap<u64, u128>,
    pub next_position_id: u64,
    pub min_health_factor: u128,
}

pub struct SwapParams {
    pub amount_in: u128,
    pub min_amount_out: u128,
    pub max_slippage_bps: u16,
}

impl PositionVault {
    fn execute_swap(&mut self, params: &SwapParams) -> u128 {
        let slippage = params.amount_in * params.max_slippage_bps as u128 / 10000;
        params.amount_in.saturating_sub(slippage)
    }

    pub fn open_position(&mut self, collateral: u128, debt: u128, swap_params: SwapParams) -> u64 {
        let position_id = self.next_position_id;
        self.next_position_id += 1;
        let received = self.execute_swap(&swap_params);
        let health_factor = if debt > 0 {
            (collateral + received) * 100 / debt
        } else {
            u128::MAX
        };
        assert!(health_factor >= self.min_health_factor, "unsafe position");
        self.positions.insert(position_id, collateral + received);
        position_id
    }
}

pub struct RoyaltyDistribution {
    pub total_amount: u128,
    pub recipients: Vec<(String, u128)>,
}

impl RoyaltyDistribution {
    pub fn distribute_with_deterministic_dust(&self) -> HashMap<String, u128> {
        let total_basis: u128 = self.recipients.iter().map(|(_, bp)| bp).sum();
        let mut distributions = HashMap::new();
        let mut total_distributed = 0u128;
        for (i, (addr, bp)) in self.recipients.iter().enumerate() {
            let mut share = (self.total_amount * bp) / total_basis;
            if i == self.recipients.len() - 1 {
                share += self.total_amount - total_distributed - share;
            }
            distributions.insert(addr.clone(), share);
            total_distributed += share;
        }
        distributions
    }
}
