pub const MODULUS: u64 = 0x7800_0001;
pub struct BabyBear;

pub struct Vault {
    pub protocol_fees: u128,
    pub rewards_paid: u128,
    pub burned_shares: u128,
}

fn ceil_div(numerator: u128, denominator: u128) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    numerator.checked_add(denominator - 1)?.checked_div(denominator)
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
        let scaled_fee = user_notional.checked_mul(protocol_fee_bps)?;
        let protocol_fee = scaled_fee.checked_div(fee_denominator)?;
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
    ) -> Option<u128> {
        let shares_to_burn = ceil_div(requested_assets, price_per_share)?;
        self.burn(caller, shares_to_burn);
        self.transfer(caller, requested_assets);
        Some(requested_assets)
    }

    pub fn claim_rewards(
        &mut self,
        user_weight: u128,
        total_weight: u128,
        epoch_reward: u128,
    ) -> Option<u128> {
        if total_weight == 0 {
            return None;
        }
        if user_weight % total_weight != 0 {
            return None;
        }
        let reward_units = user_weight / total_weight;
        let reward_payout = reward_units.checked_mul(epoch_reward)?;
        self.rewards_paid += reward_payout;
        Some(reward_payout)
    }
}

pub fn advance_field_timestamp(timestamp: u64, delta: u64) -> Option<u64> {
    let next_timestamp = timestamp.checked_add(delta)?;
    if next_timestamp >= MODULUS {
        return None;
    }
    Some(next_timestamp)
}
