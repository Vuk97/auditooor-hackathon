use std::collections::HashMap;

type Address = [u8; 32];

pub trait RoyaltyCallback {
    fn receive_royalty(&mut self, amount: u64);
}

pub trait NftReceiver {
    fn on_erc721_received(&mut self, operator: Address, from: Address, token_id: u64);
}

pub fn safe_transfer_from(_operator: Address, _from: Address, _to: Address, _token_id: u64) {}

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
    sale_status: HashMap<u64, &'static str>,
    packet_state: HashMap<u64, bool>,
}

impl RoyaltyPool {
    pub fn guarded_royalty_callback(
        &mut self,
        seller: Address,
        token_id: u64,
        price: u64,
    ) {
        non_reentrant();
        let (royalty_receiver, royalty_amount) =
            RoyaltyOracle::royalty_info(token_id, price);
        let seller_amount = price.saturating_sub(royalty_amount);

        if let Some(callback) = self.callbacks.get_mut(&royalty_receiver) {
            callback.receive_royalty(royalty_amount);
        }

        *self.balances.entry(royalty_receiver).or_insert(0) += royalty_amount;
        *self.balances.entry(seller).or_insert(0) += seller_amount;
    }

    pub fn domain_bound_and_checkpointed_royalty_callback(
        &mut self,
        seller: Address,
        token_id: u64,
        price: u64,
    ) {
        let (royalty_receiver, royalty_amount) =
            RoyaltyOracle::royalty_info(token_id, price);
        verify_royalty_domain(token_id, royalty_receiver);
        self.sale_status.insert(token_id, "Settling");

        if let Some(callback) = self.callbacks.get_mut(&royalty_receiver) {
            callback.receive_royalty(royalty_amount);
        }

        let latest_sale_after = self.sale_status.get(&token_id).copied();
        if latest_sale_after == Some("Settling") {
            *self.balances.entry(royalty_receiver).or_insert(0) += royalty_amount;
            *self.balances.entry(seller).or_insert(0) +=
                price.saturating_sub(royalty_amount);
        }
    }

    pub fn on_erc721_received_reloads_before_commit(
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

        let collateral_after = self.collateral_configs.get(&token_id).cloned();
        let mut latest_config = collateral_after.unwrap_or_default();
        latest_config.collateral_shares += 100;
        self.collateral_configs.insert(token_id, latest_config);
    }

    pub fn open_packet_mints_duplicate_card_shape_not_royalty_or_collateral(
        &mut self,
        receiver: Address,
        packet_id: u64,
    ) {
        let packet_state = self.packet_state.get(&packet_id).copied();
        safe_transfer_from(receiver, [0; 32], receiver, packet_id);
        self.packet_state.insert(packet_id, packet_state.unwrap_or(false));
    }
}

pub fn non_reentrant() {}
pub fn verify_royalty_domain(_token_id: u64, _receiver: Address) {}
