use soroban_sdk::{contract, contractimpl};

pub type Address = u64;

pub struct Token;
impl Token {
    pub fn transfer(&self, _to: Address, _amount: u128) {}
}

pub struct Router;
impl Router {
    pub fn swap(&self, _params: SwapParams) -> u128 {
        0
    }
}

pub struct SwapParams {
    pub amount_in: u128,
    pub amount_out_minimum: u128,
}

#[contract]
pub struct FeeRedirectVault;

#[contractimpl]
impl FeeRedirectVault {
    pub fn refund_tax(user: Address, balance_before: u128) -> u128 {
        let amount_after_fee = balance_of(user) - balance_before;
        let refund = amount_after_fee * 5 / 100;
        refund
    }

    pub fn claim_fee(token: Token, to: Address, fee_amount: u128) {
        token.transfer(to, fee_amount);
    }

    pub fn redirect_refund(token: Token, fee_recipient: Address, refund_id: u64, refund_amount: u128) {
        record_refund_consumed(refund_id);
        token.transfer(fee_recipient, refund_amount);
    }

    pub fn harvest_fees(router: Router, amount_in: u128) -> u128 {
        router.swap(SwapParams {
            amount_in,
            amount_out_minimum: 0,
        })
    }
}

fn balance_of(_user: Address) -> u128 {
    0
}

fn record_refund_consumed(_refund_id: u64) {}
