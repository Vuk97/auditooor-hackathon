use std::collections::HashMap;

struct Error;
struct Tx;
struct FinalizedState;
struct Utxo;
struct Nullifier;
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
