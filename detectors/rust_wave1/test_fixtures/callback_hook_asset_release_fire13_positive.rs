use std::collections::{HashMap, HashSet};

struct ReleaseHook;

impl ReleaseHook {
    fn before_release(&self, _token_id: u64) -> Result<(), &'static str> {
        Ok(())
    }
}

struct Vault {
    owner_of: HashMap<u64, u64>,
    escrow: HashMap<u64, u128>,
    pending_release: HashSet<u64>,
    release_hook: ReleaseHook,
}

impl Vault {
    fn release_with_hook(&mut self, token_id: u64, receiver: u64) -> Result<(), &'static str> {
        self.release_hook.before_release(token_id)?;

        let _locked_value = self.escrow.remove(&token_id).ok_or("missing escrow")?;
        self.owner_of.insert(token_id, receiver);
        self.pending_release.remove(&token_id);

        Ok(())
    }
}
