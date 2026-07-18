use std::collections::BTreeMap;

pub struct Account {
    pub balance: u128,
}

pub struct SafeSettlementBook {
    pub rounding_carry: u128,
    pub refunds: BTreeMap<[u8; 32], u128>,
    pub protocol_dust: u128,
}

const MAX_DUST: u128 = 3;

impl SafeSettlementBook {
    pub fn reject_non_exact_split(
        &mut self,
        participants: &mut [Account],
        total_fee: u128,
    ) -> Result<(), &'static str> {
        let share = total_fee / participants.len() as u128;
        let remainder = total_fee % participants.len() as u128;
        if remainder != 0 {
            return Err("non exact split");
        }
        for participant in participants.iter_mut() {
            participant.balance += share;
        }
        Ok(())
    }

    pub fn carry_residual_forward(
        &mut self,
        accounts: &[Account],
        total_rewards: u128,
    ) -> Option<()> {
        let per_account = total_rewards.checked_div(accounts.len() as u128)?;
        let residual = total_rewards.checked_sub(per_account.checked_mul(accounts.len() as u128)?)?;
        self.rounding_carry += residual;
        Some(())
    }

    pub fn refund_remainder_to_payer(
        &mut self,
        payer: [u8; 32],
        total_fee: u128,
        count: u128,
    ) -> Option<()> {
        let share = total_fee.checked_div(count)?;
        let remainder = total_fee.checked_rem(count)?;
        self.refunds.insert(payer, remainder);
        self.protocol_dust += share;
        Some(())
    }

    pub fn bound_dust_before_protocol_account(
        &mut self,
        collector_count: u128,
        total_fee: u128,
    ) -> Result<(), &'static str> {
        let dust = total_fee % collector_count;
        if dust > MAX_DUST {
            return Err("dust exceeds bound");
        }
        self.protocol_dust += dust;
        Ok(())
    }
}
