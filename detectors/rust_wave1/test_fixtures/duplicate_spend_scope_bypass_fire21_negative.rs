use std::collections::HashMap;

struct Error;
struct Tx;
struct FinalizedState;
struct Chain;
struct Utxo;
#[derive(Clone, Eq, Hash, PartialEq)]
struct Nullifier;
#[derive(Clone, Eq, Hash, PartialEq)]
struct OutPoint;
type Result<T> = std::result::Result<T, Error>;

impl Tx {
    fn sapling_nullifiers(&self) -> Vec<Nullifier> {
        vec![]
    }
}

impl FinalizedState {
    fn contains_sapling_nullifier(&self, _n: &Nullifier) -> bool {
        false
    }

    fn utxo(&self, _spend: &OutPoint) -> Option<Utxo> {
        None
    }
}

impl Chain {
    fn sapling_nullifiers_contains_key(&self, _n: &Nullifier) -> bool {
        false
    }
}

fn validate_transaction_nullifier_scope(
    tx: &Tx,
    finalized_state: &FinalizedState,
    non_finalized_chain: Option<&Chain>,
) -> Result<()> {
    for nullifier in tx.sapling_nullifiers() {
        if let Some(true) = non_finalized_chain
            .as_ref()
            .map(|chain| chain.sapling_nullifiers_contains_key(&nullifier))
        {
            return Err(Error);
        } else if finalized_state.contains_sapling_nullifier(&nullifier) {
            return Err(Error);
        }
    }

    Ok(())
}

fn validate_transparent_spend_scope(
    spend: OutPoint,
    block_new_outputs: &HashMap<OutPoint, Utxo>,
    non_finalized_chain_spent_utxos: &HashMap<OutPoint, ()>,
    non_finalized_chain_unspent_utxos: &HashMap<OutPoint, Utxo>,
    finalized_state: &FinalizedState,
) -> Result<Utxo> {
    if let Some(output) = block_new_outputs.get(&spend) {
        return Ok(output.clone());
    }

    if non_finalized_chain_spent_utxos.contains_key(&spend) {
        return Err(Error);
    }

    non_finalized_chain_unspent_utxos
        .get(&spend)
        .cloned()
        .or_else(|| finalized_state.utxo(&spend))
        .ok_or(Error)
}

struct ReceiptIndex {
    spent_receipts: HashMap<(u32, u32, u32, u64, u64), ()>,
}

impl ReceiptIndex {
    pub fn record_receipt_spend_scope(
        &mut self,
        chain_id: u32,
        asset_id: u32,
        branch_id: u32,
        tx_id: u64,
        receipt_id: u64,
    ) -> Result<()> {
        let scoped_key = (chain_id, asset_id, branch_id, tx_id, receipt_id);

        if self.spent_receipts.contains_key(&scoped_key) {
            return Err(Error);
        }

        self.spent_receipts.insert(scoped_key, ());
        Ok(())
    }
}
