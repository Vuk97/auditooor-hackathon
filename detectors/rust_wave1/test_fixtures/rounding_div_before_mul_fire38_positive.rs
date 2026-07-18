pub const MODULUS: u64 = 0x7800_0001;
pub struct BabyBear;

pub struct Vault {
    pub protocol_fees: u128,
    pub rewards_paid: u128,
    pub burned_shares: u128,
}

impl Vault {
    pub fn transfer(&mut self, _caller: u64, _assets: u128) {}
    pub fn burn(&mut self, _caller: u64, shares: u128) {
        self.burned_shares += shares;
    }

    pub fn charge_exit_fee(
        &mut self,
        caller: u64,
        user_notional: u128,
        fee_denominator: u128,
        protocol_fee_bps: u128,
    ) -> Option<u128> {
        let protocol_fee = user_notional.checked_div(fee_denominator)?.checked_mul(protocol_fee_bps)?;
        let net_assets = user_notional.checked_sub(protocol_fee)?;
        self.protocol_fees += protocol_fee;
        self.transfer(caller, net_assets);
        Some(net_assets)
    }

    pub fn redeem_exact_assets(
        &mut self,
        caller: u64,
        requested_assets: u128,
        price_per_share: u128,
    ) -> u128 {
        let shares_to_burn = requested_assets / price_per_share;
        self.burn(caller, shares_to_burn);
        self.transfer(caller, requested_assets);
        requested_assets
    }

    pub fn claim_rewards(
        &mut self,
        user_weight: u128,
        total_weight: u128,
        epoch_reward: u128,
    ) -> u128 {
        let reward_units = user_weight / total_weight;
        let reward_payout = reward_units * epoch_reward;
        self.rewards_paid += reward_payout;
        reward_payout
    }
}

pub fn advance_field_timestamp(timestamp: u64, delta: u64) -> u64 {
    let next_timestamp = timestamp + delta;
    let clamped_timestamp = next_timestamp.min(MODULUS - 1);
    clamped_timestamp
}
