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
    CallbackFailed,
}

struct PacketState {
    opened: bool,
    amount: u128,
}

struct PacketProgram;

impl PacketProgram {
    fn invoke(&self, _packet_id: u64) -> Result<(), Error> {
        Ok(())
    }
}

pub struct Fire37Vault {
    balances: BTreeMap<Address, u128>,
    shares: BTreeMap<Address, u128>,
    claims: BTreeMap<u64, ClaimStatus>,
    packets: BTreeMap<u64, PacketState>,
}

impl Fire37Vault {
    pub fn claim_with_receiver_callback(
        &mut self,
        user: Address,
        receiver: &mut dyn ClaimReceiver,
        claim_id: u64,
        amount: u128,
    ) -> Result<(), Error> {
        let balance_before = self.balances.get(&user).copied().unwrap_or(0);
        let shares_before = self.shares.get(&user).copied().unwrap_or(0);
        let claim_state = self.claims.get(&claim_id).copied().unwrap_or(ClaimStatus::Pending);

        if claim_state == ClaimStatus::Claimed {
            return Err(Error::AlreadyClaimed);
        }
        if balance_before < amount {
            return Err(Error::InsufficientBalance);
        }

        receiver.on_claim(user, amount).map_err(|_| Error::CallbackFailed)?;

        self.balances.insert(user, balance_before - amount);
        self.shares.insert(user, shares_before.saturating_sub(amount));
        self.claims.insert(claim_id, ClaimStatus::Claimed);
        Ok(())
    }

    pub fn open_packet_with_cpi(
        &mut self,
        packet_id: u64,
        receiver_program: &PacketProgram,
    ) -> Result<(), Error> {
        let packet_state = self.packets.get(&packet_id).map(|p| p.amount).unwrap_or(0);

        receiver_program.invoke(packet_id)?;

        self.packets.insert(
            packet_id,
            PacketState {
                opened: true,
                amount: packet_state,
            },
        );
        Ok(())
    }
}
