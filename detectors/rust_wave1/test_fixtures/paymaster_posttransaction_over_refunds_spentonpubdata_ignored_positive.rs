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

pub struct BuggyPaymaster;

impl Paymaster for BuggyPaymaster {
    fn post_transaction(
        &mut self,
        ctx: &mut PaymasterContext,
        tx_result: &TransactionResult,
        max_refunded_gas: u64,
    ) -> u64 {
        // BUG: spent_on_pubdata is IGNORED in refund calculation
        // This allows over-refunding since max_refunded_gas is not reduced
        let refund = min(tx_result.gas_used, max_refunded_gas);
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
    fn test_buggy_paymaster_over_refunds() {
        let mut paymaster = BuggyPaymaster;
        let mut ctx = PaymasterContext { balance: 1000 };
        let tx_result = TransactionResult {
            gas_used: 150,
            spent_on_pubdata: 30,
        };
        let max_refunded = 150;
        let refund = process_transaction(&mut paymaster, &mut ctx, &tx_result, max_refunded);
        // BUG: should be 120 (150 - 30), but gets 150
        assert_eq!(refund, 150); // over-refunded by 30
        assert_eq!(ctx.balance, 850); // drained by extra 30
    }
}
