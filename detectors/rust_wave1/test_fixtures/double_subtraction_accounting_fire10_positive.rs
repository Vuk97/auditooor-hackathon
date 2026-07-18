use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct AccountingPool {
    balances: Map<u64, u128>,
    total_reserve: u128,
}

#[contractimpl]
impl AccountingPool {
    pub fn withdraw_double_debits_balance(
        &mut self,
        user: u64,
        principal: u128,
        exit_fee: u128,
    ) {
        let starting_balance = self.balances.get(&user).unwrap_or(0);
        self.balances.insert(&user, starting_balance - principal);

        let after_principal = self.balances.get(&user).unwrap_or(0);
        self.balances.insert(&user, after_principal - exit_fee);
    }

    pub fn burn_reserve_and_fee_independently(&mut self, amount: u128, fee: u128) {
        self.total_reserve -= amount;
        self.total_reserve -= fee;
    }
}
