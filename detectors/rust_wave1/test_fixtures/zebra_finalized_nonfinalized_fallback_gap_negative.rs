use std::{collections::HashMap, sync::Arc};

struct OutPoint;
struct OrderedUtxo;
struct SpendingTransactionId;
struct SaplingAnchor;
struct ZebraDb;
struct Chain {
    sapling_anchors: Vec<SaplingAnchor>,
}

impl ZebraDb {
    fn utxo(&self, _outpoint: &OutPoint) -> Option<OrderedUtxo> {
        None
    }

    fn contains_sapling_anchor(&self, _anchor: &SaplingAnchor) -> bool {
        false
    }
}

pub fn validate_spend_chain_order(
    non_finalized_chain_unspent_utxos: &HashMap<OutPoint, OrderedUtxo>,
    non_finalized_chain_spent_utxos: &HashMap<OutPoint, SpendingTransactionId>,
    finalized_state: &ZebraDb,
    spend: OutPoint,
) -> Option<OrderedUtxo> {
    if non_finalized_chain_spent_utxos.contains_key(&spend) {
        return None;
    }

    non_finalized_chain_unspent_utxos
        .get(&spend)
        .cloned()
        .or_else(|| finalized_state.utxo(&spend))
}

pub fn sapling_anchor_refer_to_final_treestates(
    finalized_state: &ZebraDb,
    parent_chain: Option<&Arc<Chain>>,
    anchor: &SaplingAnchor,
) -> bool {
    parent_chain
        .map(|chain| chain.sapling_anchors.contains(anchor))
        .unwrap_or(false)
        || finalized_state.contains_sapling_anchor(anchor)
}
