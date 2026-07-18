// Clean fixture: confirmation count computed with checked_sub guard.
// Should NOT fire.

pub fn mined_transaction_safe(chain: Option<Chain>, db: &ZebraDb, hash: TxHash) -> Option<MinedTx> {
    // # Correctness
    //
    // It is ok to do this lookup in two different calls. Finalized state updates
    // can only add overlapping blocks, and hashes are unique.
    let chain = chain.as_ref();

    let (tx, height, time) = transaction(chain, db, hash)?;
    let tip = tip_height(chain, db)?;
    // Use checked_sub to avoid u32 underflow on reorg
    let confirmations = 1u64 + tip.0.checked_sub(height.0)? as u64;

    Some(MinedTx::new(tx, height, confirmations, time))
}

// Also clean: casts to i64 before subtraction
pub fn any_transaction_safe<'a>(
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
    let (tx, height, time, in_best_chain) = find_tx(chains, db, hash)?;

    if in_best_chain {
        let tip = tip_height(best_chain, db)?;
        // Cast to signed before subtracting to avoid u32 underflow
        let diff = (tip.0 as i64) - (height.0 as i64);
        let confirmations = if diff >= 0 { 1 + diff as u64 } else { 0 };
        Some(AnyTx::Mined(MinedTx::new(tx, height, confirmations, time)))
    } else {
        Some(AnyTx::Side(tx))
    }
}

// Also clean: no tip_height call at all (unrelated depth function)
pub fn block_depth(block_height: u32, target_height: u32) -> u32 {
    block_height.saturating_sub(target_height)
}
