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

pub struct Claims;
impl Claims {
    pub fn insert(&mut self, _id: u64, _value: bool) {}
}

pub struct FeeConfig {
    pub fee_recipient: Address,
}

pub struct SwapParams {
    pub amount_in: u128,
    pub amount_out_minimum: u128,
}

#[contract]
pub struct SafeFeeRedirectVault {
    pub config: FeeConfig,
    pub claimed: Claims,
}

#[contractimpl]
impl SafeFeeRedirectVault {
    pub fn refund_tax(_user: Address, input_amount: u128) -> u128 {
        let gross_amount = input_amount;
        let refund = gross_amount * 5 / 100;
        refund
    }

    pub fn claim_fee(&mut self, token: Token, fee_recipient: Address, claim_id: u64, fee_amount: u128) {
        assert_eq!(fee_recipient, self.config.fee_recipient);
        self.claimed.insert(claim_id, true);
        token.transfer(fee_recipient, fee_amount);
    }

    pub fn redirect_refund(&mut self, token: Token, fee_recipient: Address, refund_id: u64, refund_amount: u128) {
        assert_eq!(fee_recipient, self.config.fee_recipient);
        self.claimed.insert(refund_id, true);
        token.transfer(fee_recipient, refund_amount);
    }

    pub fn harvest_fees(router: Router, amount_in: u128, expected_out: u128) -> u128 {
        let min_out = expected_out * 99 / 100;
        router.swap(SwapParams {
            amount_in,
            amount_out_minimum: min_out,
        })
    }
}
