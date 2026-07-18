pub struct RedemptionState {
    pub balances: std::collections::BTreeMap<u64, u128>,
    pub finalized_redemptions: std::collections::BTreeSet<u64>,
}

pub trait RedeemCallback {
    fn on_redeem(&self, user: u64, request_id: u64);
}

pub fn redeem_without_precommit(
    state: &mut RedemptionState,
    receiver: &dyn RedeemCallback,
    user: u64,
    request_id: u64,
    shares: u128,
) {
    receiver.on_redeem(user, request_id);

    state.finalized_redemptions.insert(request_id);
    state.balances.insert(user, state.balances[&user] - shares);
}
