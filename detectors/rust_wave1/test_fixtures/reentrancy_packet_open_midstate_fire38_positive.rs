use std::collections::BTreeMap;

type Address = u64;

trait PacketReceiver {
    fn safe_mint(&mut self, user: Address, card_id: u64) -> Result<(), Error>;
    fn on_reward(&mut self, user: Address, amount: u128) -> Result<(), Error>;
}

trait NftHook {
    fn on_receive_nft(&mut self, user: Address, token_id: u64) -> Result<(), Error>;
}

#[derive(Clone, Copy)]
struct PacketState {
    opened: bool,
    reward_amount: u128,
    next_card_id: u64,
}

#[derive(Clone, Copy)]
struct CardState {
    owner: Address,
    packet_id: u64,
}

#[derive(Debug)]
enum Error {
    AlreadyOpened,
    CallbackFailed,
    InsufficientRewards,
}

pub struct Fire38PacketVault {
    packets: BTreeMap<u64, PacketState>,
    cards: BTreeMap<u64, CardState>,
    rewards: BTreeMap<Address, u128>,
    shares: BTreeMap<Address, u128>,
    collateral: BTreeMap<Address, u128>,
}

impl Fire38PacketVault {
    pub fn open_packet_mints_before_marking_open(
        &mut self,
        user: Address,
        packet_id: u64,
        receiver: &mut dyn PacketReceiver,
    ) -> Result<(), Error> {
        let packet_snapshot = self.packets.get(&packet_id).copied().unwrap();
        let card_snapshot = packet_snapshot.next_card_id;

        if packet_snapshot.opened {
            return Err(Error::AlreadyOpened);
        }

        receiver.safe_mint(user, card_snapshot).map_err(|_| Error::CallbackFailed)?;

        self.cards.insert(
            card_snapshot,
            CardState {
                owner: user,
                packet_id,
            },
        );
        self.packets.insert(
            packet_id,
            PacketState {
                opened: true,
                reward_amount: packet_snapshot.reward_amount,
                next_card_id: card_snapshot + 1,
            },
        );
        Ok(())
    }

    pub fn on_erc721_received_updates_collateral_after_hook(
        &mut self,
        user: Address,
        token_id: u64,
        hook: &mut dyn NftHook,
    ) -> Result<(), Error> {
        let collateral_snapshot = self.collateral.get(&user).copied().unwrap_or(0);
        let reward_snapshot = self.rewards.get(&user).copied().unwrap_or(0);

        hook.on_receive_nft(user, token_id).map_err(|_| Error::CallbackFailed)?;

        self.collateral.insert(user, collateral_snapshot + 1);
        self.rewards.insert(user, reward_snapshot + 10);
        Ok(())
    }

    pub fn withdraw_rewards_transfers_before_reward_update(
        &mut self,
        user: Address,
        receiver: &mut dyn PacketReceiver,
        amount: u128,
    ) -> Result<(), Error> {
        let reward_snapshot = self.rewards.get(&user).copied().unwrap_or(0);
        let share_snapshot = self.shares.get(&user).copied().unwrap_or(0);
        if reward_snapshot < amount {
            return Err(Error::InsufficientRewards);
        }

        receiver.on_reward(user, amount).map_err(|_| Error::CallbackFailed)?;

        self.update_account_rewards(user, share_snapshot, reward_snapshot - amount);
        Ok(())
    }

    fn update_account_rewards(&mut self, user: Address, shares: u128, rewards: u128) {
        self.shares.insert(user, shares);
        self.rewards.insert(user, rewards);
    }
}
