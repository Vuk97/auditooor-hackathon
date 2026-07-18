use std::collections::HashMap;

type Address = [u8; 32];

pub trait RoyaltyCallback {
    fn receive_royalty(&mut self, amount: u64);
}

pub trait NftReceiver {
    fn on_erc721_received(&mut self, operator: Address, from: Address, token_id: u64);
}

pub struct RoyaltyOracle;

impl RoyaltyOracle {
    pub fn royalty_info(_token_id: u64, sale_price: u64) -> (Address, u64) {
        ([0xAA; 32], sale_price / 10)
    }
}

#[derive(Clone, Default)]
pub struct CollateralConfig {
    pub collateral_shares: u64,
}

pub struct RoyaltyPool {
    balances: HashMap<Address, u64>,
    callbacks: HashMap<Address, Box<dyn RoyaltyCallback>>,
    collateral_configs: HashMap<u64, CollateralConfig>,
}

impl RoyaltyPool {
    pub fn buy_with_stale_royalty_callback(
        &mut self,
        buyer: Address,
        seller: Address,
        token_id: u64,
        price: u64,
    ) {
        let (royalty_receiver, royalty_amount) =
            RoyaltyOracle::royalty_info(token_id, price);
        let seller_amount = price.saturating_sub(royalty_amount);

        if let Some(callback) = self.callbacks.get_mut(&royalty_receiver) {
            callback.receive_royalty(royalty_amount);
        }

        *self.balances.entry(royalty_receiver).or_insert(0) += royalty_amount;
        *self.balances.entry(seller).or_insert(0) += seller_amount;
        *self.balances.entry(buyer).or_insert(0) -= price;
    }

    pub fn on_erc721_received_reenters_before_share_commit(
        &mut self,
        receiver: &mut dyn NftReceiver,
        operator: Address,
        from: Address,
        token_id: u64,
    ) {
        let mut collateral_config = self
            .collateral_configs
            .get(&token_id)
            .cloned()
            .unwrap_or_default();
        collateral_config.collateral_shares += 100;

        receiver.on_erc721_received(operator, from, token_id);

        self.collateral_configs.insert(token_id, collateral_config);
    }
}
