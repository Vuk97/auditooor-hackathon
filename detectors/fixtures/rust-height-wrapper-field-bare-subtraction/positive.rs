// positive.rs - SHOULD fire: bare .0 - .0 subtraction on Height newtypes

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Height(pub u32);

pub struct ZebraDb;
pub struct Chain;
pub struct MinedTx;
pub struct Transaction;

fn tip_height(_chain: Option<&Chain>, _db: &ZebraDb) -> Option<Height> {
    Some(Height(100))
}

fn height_by_hash(_chain: Option<&Chain>, _db: &ZebraDb, _hash: u64) -> Option<Height> {
    Some(Height(90))
}

fn transaction(_chain: Option<&Chain>, _db: &ZebraDb, _hash: u64) -> Option<(Transaction, Height, u64)> {
    None
}

// Case 1: simple depth function - mirrors find.rs:154
pub fn depth(chain: Option<&Chain>, db: &ZebraDb, hash: u64) -> Option<u32> {
    let tip = tip_height(chain, db)?;
    let height = height_by_hash(chain, db, hash)?;
    // UNSAFE: bare .0 subtraction - panics in debug if reorg makes tip < height
    Some(tip.0 - height.0)
}

// Case 2: confirmations with addition chain - mirrors block.rs:156
pub fn mined_transaction(chain: Option<&Chain>, db: &ZebraDb, hash: u64) -> Option<MinedTx> {
    let (_, height, _) = transaction(chain, db, hash)?;
    // UNSAFE: 1 + tip.0 - height.0 wraps silently on underflow
    let confirmations = 1 + tip_height(chain, db)?.0 - height.0;
    let _ = confirmations;
    Some(MinedTx)
}
