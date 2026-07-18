use std::cmp::min;

#[derive(Clone, Debug, Default)]
pub struct TransactionResult {
    pub gas_used: u64,
    pub spent_on_pubdata: u64,
}

#[derive(Clone, Debug, Default)]
pub struct PaymasterContext {
    pub balance: u64,
}

pub trait Paymaster {
    fn post_transaction(
        &mut self,
        ctx: &mut PaymasterContext,
        tx_result: &TransactionResult,
        max_refunded_gas: u64,
    ) -> u64;
}

pub struct HonestPaymaster;

impl Paymaster for HonestPaymaster {
    fn post_transaction(
        &mut self,
        ctx: &mut PaymasterContext,
        tx_result: &TransactionResult,
        max_refunded_gas: u64,
    ) -> u64 {
        // CORRECT: subtract spent_on_pubdata from refund calculation
        let actual_refundable = max_refunded_gas.saturating_sub(tx_result.spent_on_pubdata);
        let refund = min(tx_result.gas_used, actual_refundable);
        ctx.balance = ctx.balance.saturating_sub(refund);
        refund
    }
}

pub fn process_transaction<P: Paymaster>(
    paymaster: &mut P,
    ctx: &mut PaymasterContext,
    tx_result: &TransactionResult,
    max_refunded_gas: u64,
) -> u64 {
    paymaster.post_transaction(ctx, tx_result, max_refunded_gas)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honest_paymaster_does_not_over_refund() {
        let mut paymaster = HonestPaymaster;
        let mut ctx = PaymasterContext { balance: 1000 };
        let tx_result = TransactionResult {
            gas_used: 100,
            spent_on_pubdata: 30,
        };
        let max_refunded = 150;
        let refund = process_transaction(&mut paymaster, &mut ctx, &tx_result, max_refunded);
        assert_eq!(refund, 100); // capped by gas_used, not 150
        assert_eq!(ctx.balance, 900);
    }
}
