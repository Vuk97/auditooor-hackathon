// A4 fixture: HashSet-insert uniqueness idiom, one guarded + one unguarded.
pub fn spend_guarded(nullifier: [u8; 32], nullifiers: &mut HashSet<[u8; 32]>) -> Result<()> {
    // HashSet::insert returns false if already present -> require! is the guard.
    require!(nullifiers.insert(nullifier), ErrorCode::AlreadySpent);
    Ok(())
}

pub fn spend_unguarded(nullifier: [u8; 32], nullifiers: &mut HashSet<[u8; 32]>) -> Result<()> {
    // bare insert: a replayed nullifier is silently accepted -> MUST fire.
    nullifiers.insert(nullifier);
    Ok(())
}
