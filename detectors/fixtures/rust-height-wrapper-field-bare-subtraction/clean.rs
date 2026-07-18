// clean.rs - should NOT fire: safe patterns only

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Height(pub u32);

#[derive(Copy, Clone)]
pub struct HeightDiff(pub i64);

impl std::ops::Sub for Height {
    type Output = HeightDiff;
    // Sub trait impl: bare .0 - .0 here is the operator definition, NOT a bug
    fn sub(self, rhs: Height) -> HeightDiff {
        HeightDiff((self.0 as i64) - (rhs.0 as i64))
    }
}

pub struct ZebraDb;
pub struct Chain;

fn tip_height(_chain: Option<&Chain>, _db: &ZebraDb) -> Option<Height> {
    Some(Height(100))
}

fn height_by_hash(_chain: Option<&Chain>, _db: &ZebraDb, _hash: u64) -> Option<Height> {
    Some(Height(90))
}

// Case 1: uses the safe Sub trait (Height - Height -> HeightDiff)
pub fn depth_safe(chain: Option<&Chain>, db: &ZebraDb, hash: u64) -> Option<i64> {
    let tip = tip_height(chain, db)?;
    let height = height_by_hash(chain, db, hash)?;
    // SAFE: uses Height::Sub which returns HeightDiff (i64)
    Some((tip - height).0)
}

// Case 2: uses checked_sub
pub fn depth_checked(chain: Option<&Chain>, db: &ZebraDb, hash: u64) -> Option<u32> {
    let tip = tip_height(chain, db)?;
    let height = height_by_hash(chain, db, hash)?;
    // SAFE: checked_sub returns None on underflow
    tip.0.checked_sub(height.0)
}

// Case 3: uses saturating_sub
pub fn depth_saturating(chain: Option<&Chain>, db: &ZebraDb, hash: u64) -> Option<u32> {
    let tip = tip_height(chain, db)?;
    let height = height_by_hash(chain, db, hash)?;
    // SAFE: saturating_sub clamps to 0 on underflow
    Some(tip.0.saturating_sub(height.0))
}

// Case 4: non-height type subtract (cryptographic field - different domain, no bug)
pub struct ValueCommitment(pub u64);
impl std::ops::Sub<ValueCommitment> for ValueCommitment {
    type Output = Self;
    fn sub(self, rhs: ValueCommitment) -> Self::Output {
        ValueCommitment(self.0 - rhs.0)
    }
}
