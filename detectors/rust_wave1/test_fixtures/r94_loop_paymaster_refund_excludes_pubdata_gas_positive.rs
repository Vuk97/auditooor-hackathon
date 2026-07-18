use soroban_sdk::{contract, contractimpl};
pub struct TxContext { gas_used: u64, spent_on_pubdata: u64, gas_price: u64 }
fn transfer_to_user(_amount: u64) {}
#[contract]
pub struct Paymaster;
#[contractimpl]
impl Paymaster {
    // BUG: refund includes pubdata gas (does not subtract spentOnPubdata)
    pub fn post_transaction(ctx: TxContext, gas_limit: u64) {
        let max_refunded_gas = gas_limit.saturating_sub(ctx.gas_used);
        let refund = max_refunded_gas * ctx.gas_price;
        transfer_to_user(refund);
    }
}
