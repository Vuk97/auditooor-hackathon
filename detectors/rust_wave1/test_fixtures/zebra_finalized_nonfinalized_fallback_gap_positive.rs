use std::collections::HashMap;

struct OutPoint;
struct OrderedUtxo;
struct ZebraDb;

impl ZebraDb {
    fn utxo(&self, _outpoint: &OutPoint) -> Option<OrderedUtxo> {
        None
    }
}

pub fn validate_spend_chain_order(
    non_finalized_chain_unspent_utxos: &HashMap<OutPoint, OrderedUtxo>,
    finalized_state: &ZebraDb,
    spend: OutPoint,
) -> Option<OrderedUtxo> {
    non_finalized_chain_unspent_utxos
        .get(&spend)
        .cloned()
        .or_else(|| finalized_state.utxo(&spend))
}
