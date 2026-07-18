use std::collections::BTreeMap;

type Address = u64;

trait ClaimReceiver {
    fn on_claim(&mut self, user: Address, amount: u128) -> Result<(), Error>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimStatus {
    Pending,
    Claimed,
}

#[derive(Debug)]
enum Error {
    AlreadyClaimed,
    InsufficientBalance,
    Reentrant,
    CallbackFailed,
}

pub struct Fire37VaultSafe {
    balances: BTreeMap<Address, u128>,
    shares: BTreeMap<Address, u128>,
    claims: BTreeMap<u64, ClaimStatus>,
    reentrancy_lock: bool,
}

impl Fire37VaultSafe {
    pub fn claim_with_reentrancy_lock(
        &mut self,
        user: Address,
        receiver: &mut dyn ClaimReceiver,
        claim_id: u64,
        amount: u128,
    ) -> Result<(), Error> {
        if self.reentrancy_lock {
            return Err(Error::Reentrant);
        }
        self.reentrancy_lock = true;

        let balance_before = self.balances.get(&user).copied().unwrap_or(0);
        if balance_before < amount {
            self.reentrancy_lock = false;
            return Err(Error::InsufficientBalance);
        }

        receiver.on_claim(user, amount).map_err(|_| Error::CallbackFailed)?;

        self.balances.insert(user, balance_before - amount);
        self.claims.insert(claim_id, ClaimStatus::Claimed);
        self.reentrancy_lock = false;
        Ok(())
    }

    pub fn claim_refreshes_after_callback(
        &mut self,
        user: Address,
        receiver: &mut dyn ClaimReceiver,
        claim_id: u64,
        amount: u128,
    ) -> Result<(), Error> {
        let balance_before = self.balances.get(&user).copied().unwrap_or(0);
        if balance_before < amount {
            return Err(Error::InsufficientBalance);
        }

        receiver.on_claim(user, amount).map_err(|_| Error::CallbackFailed)?;

        let balance_after = self.balances.get(&user).copied().unwrap_or(0);
        if balance_after < amount {
            return Err(Error::InsufficientBalance);
        }

        self.balances.insert(user, balance_after - amount);
        self.claims.insert(claim_id, ClaimStatus::Claimed);
        Ok(())
    }

    pub fn claim_cei_before_callback(
        &mut self,
        user: Address,
        receiver: &mut dyn ClaimReceiver,
        claim_id: u64,
        amount: u128,
    ) -> Result<(), Error> {
        let balance_before = self.balances.get(&user).copied().unwrap_or(0);
        let shares_before = self.shares.get(&user).copied().unwrap_or(0);
        if balance_before < amount {
            return Err(Error::InsufficientBalance);
        }

        self.balances.insert(user, balance_before - amount);
        self.shares.insert(user, shares_before.saturating_sub(amount));
        self.claims.insert(claim_id, ClaimStatus::Claimed);

        receiver.on_claim(user, amount).map_err(|_| Error::CallbackFailed)?;
        Ok(())
    }
}
