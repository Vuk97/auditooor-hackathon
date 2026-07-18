pub struct Account {
    pub balance: u128,
    pub paid: u128,
}

pub struct SettlementBook {
    pub protocol_dust: u128,
}

impl SettlementBook {
    pub fn distribute_fee_remainder_to_first_participant(
        &mut self,
        participants: &mut [Account],
        total_fee: u128,
    ) {
        let share = total_fee / participants.len() as u128;
        for participant in participants.iter_mut() {
            participant.balance += share;
        }
        let remainder = total_fee % participants.len() as u128;
        participants[0].balance += remainder;
    }

    pub fn credit_reward_residual_to_last_receiver(
        &mut self,
        receivers: &mut [Account],
        total_rewards: u128,
    ) {
        let per_receiver = total_rewards / receivers.len() as u128;
        for receiver in receivers.iter_mut() {
            receiver.paid += per_receiver;
        }
        let residual = total_rewards - per_receiver * receivers.len() as u128;
        receivers.last_mut().unwrap().paid += residual;
    }

    pub fn send_checked_dust_to_module_account(
        &mut self,
        collector_count: u128,
        total_fee: u128,
    ) -> Option<()> {
        let share = total_fee.checked_div(collector_count)?;
        let dust = total_fee.checked_rem(collector_count)?;
        self.protocol_dust += dust;
        self.protocol_dust += share;
        Some(())
    }

    pub fn pay_leftover_to_attacker_sink(
        &mut self,
        accounts: &[Account],
        caller: [u8; 32],
        total_payout: u128,
    ) -> Option<()> {
        let share = total_payout.checked_div(accounts.len() as u128)?;
        let leftover = total_payout.checked_sub(share.checked_mul(accounts.len() as u128)?)?;
        self.credit(caller, leftover);
        Some(())
    }

    fn credit(&mut self, _caller: [u8; 32], amount: u128) {
        self.protocol_dust += amount;
    }
}
