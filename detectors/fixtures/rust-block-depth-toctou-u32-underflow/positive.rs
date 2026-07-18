// Positive fixture: bare u32 confirmation arithmetic across two separate
// tip_height + transaction lookup calls, with no checked_sub guard.
// Should fire.

pub fn mined_transaction(chain: Option<Chain>, db: &ZebraDb, hash: TxHash) -> Option<MinedTx> {
    // # Correctness
    //
    // It is ok to do this lookup in two different calls. Finalized state updates
    // can only add overlapping blocks, and hashes are unique.
    let chain = chain.as_ref();

    let (tx, height, time) = transaction(chain, db, hash)?;
    let confirmations = 1 + tip_height(chain, db)?.0 - height.0;

    Some(MinedTx::new(tx, height, confirmations, time))
}

pub fn any_transaction<'a>(
    chains: impl Iterator<Item = &'a Arc<Chain>>,
    db: &ZebraDb,
    hash: TxHash,
) -> Option<AnyTx> {
    // # Correctness
    //
    // It is ok to do this lookup in multiple different calls. Finalized state
    // updates can only add overlapping blocks, and hashes are unique.
    let mut chains = chains.peekable();
    let best_chain = chains.peek().copied();

    let (tx, height, time, in_best_chain) = chains
        .enumerate()
        .find_map(|(i, chain)| {
            chain.transaction(hash).map(|(tx, h, t)| (tx, h, t, i == 0))
        })
        .or_else(|| {
            db.transaction(hash).map(|(tx, h, t)| (tx, h, t, true))
        })?;

    if in_best_chain {
        let confirmations = 1 + tip_height(best_chain, db)?.0 - height.0;
        Some(AnyTx::Mined(MinedTx::new(tx, height, confirmations, time)))
    } else {
        Some(AnyTx::Side(tx))
    }
}
