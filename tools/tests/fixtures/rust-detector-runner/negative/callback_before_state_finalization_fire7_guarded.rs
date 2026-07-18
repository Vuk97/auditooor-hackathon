pub struct RedemptionState {
    pub pending_redemptions: std::collections::BTreeSet<u64>,
    pub balances: std::collections::BTreeMap<u64, u128>,
}

pub trait RedeemCallback {
    fn on_redeem(&self, user: u64, request_id: u64);
}

pub fn redeem_with_precommit(
    state: &mut RedemptionState,
    receiver: &dyn RedeemCallback,
    user: u64,
    request_id: u64,
    shares: u128,
) {
    non_reentrant();
    state.pending_redemptions.insert(request_id);

    receiver.on_redeem(user, request_id);

    state.balances.insert(user, state.balances[&user] - shares);
    state.pending_redemptions.remove(&request_id);
}

fn non_reentrant() {}
