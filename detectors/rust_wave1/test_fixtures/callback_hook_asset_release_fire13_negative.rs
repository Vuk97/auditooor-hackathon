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
    fn release_with_hook(
        &mut self,
        token_id: u64,
        receiver: u64,
        caller: u64,
    ) -> Result<(), &'static str> {
        let owner = *self.owner_of.get(&token_id).ok_or("missing owner")?;
        if caller != owner {
            return Err("not owner");
        }

        self.pending_release.insert(token_id);
        let _locked_value = self.escrow.remove(&token_id).ok_or("missing escrow")?;

        self.release_hook.before_release(token_id)?;

        self.owner_of.insert(token_id, receiver);
        self.pending_release.remove(&token_id);

        Ok(())
    }

    fn unwrap_partial_settled(&mut self, token_id: u64, amount: u128) -> Result<(), &'static str> {
        self.collect_fees(token_id)?;
        let position = self.load_position(token_id)?;
        let mut next_position = position.clone();
        next_position.liquidity -= amount;
        self.save_position(token_id, next_position);
        Ok(())
    }

    fn collect_fees(&mut self, _token_id: u64) -> Result<(), &'static str> {
        Ok(())
    }

    fn load_position(&self, _token_id: u64) -> Result<Position, &'static str> {
        Ok(Position { liquidity: 100 })
    }

    fn save_position(&mut self, _token_id: u64, _position: Position) {}
}

#[derive(Clone)]
struct Position {
    liquidity: u128,
}
