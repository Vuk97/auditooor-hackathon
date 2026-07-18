use std::collections::HashMap;

struct Error;
struct Tx;
struct FinalizedState;
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
}

fn validate_transaction_nullifier_scope(
    tx: &Tx,
    finalized_state: &FinalizedState,
) -> Result<()> {
    for nullifier in tx.sapling_nullifiers() {
        if finalized_state.contains_sapling_nullifier(&nullifier) {
            return Err(Error);
        }
    }

    Ok(())
}

fn validate_transparent_spend_scope(
    spend: OutPoint,
    non_finalized_chain_spent_utxos: &HashMap<OutPoint, ()>,
    non_finalized_chain_unspent_utxos: &HashMap<OutPoint, Utxo>,
) -> Result<Utxo> {
    if non_finalized_chain_spent_utxos.contains_key(&spend) {
        return Err(Error);
    }

    non_finalized_chain_unspent_utxos
        .get(&spend)
        .cloned()
        .ok_or(Error)
}

struct ReceiptIndex {
    spent_receipts: HashMap<u64, ()>,
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
        let _context_available = (chain_id, asset_id, branch_id, tx_id);

        if self.spent_receipts.contains_key(&receipt_id) {
            return Err(Error);
        }

        self.spent_receipts.insert(receipt_id, ());
        Ok(())
    }
}
