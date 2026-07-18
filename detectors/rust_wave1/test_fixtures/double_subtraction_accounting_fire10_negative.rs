use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct AccountingPool {
    balances: Map<u64, u128>,
    total_reserve: u128,
    protocol_reserve: u128,
}

#[contractimpl]
impl AccountingPool {
    pub fn withdraw_with_single_checked_delta(
        &mut self,
        user: u64,
        principal: u128,
        exit_fee: u128,
    ) {
        let total_debit = principal.checked_add(exit_fee).expect("overflow");
        let starting_balance = self.balances.get(&user).unwrap_or(0);
        let remaining = starting_balance.checked_sub(total_debit).expect("underflow");
        self.balances.insert(&user, remaining);
        self.total_reserve -= total_debit;
    }

    pub fn split_protocol_fee_to_distinct_ledger(
        &mut self,
        amount: u128,
        protocol_fee: u128,
    ) {
        self.total_reserve -= amount;
        self.protocol_reserve -= protocol_fee;
    }
}
