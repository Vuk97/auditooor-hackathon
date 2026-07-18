use soroban_sdk::{contract, contractimpl};

pub struct ExactInputSingleParams {
    pub amount_in: u128,
    pub amount_out_minimum: u128,
    pub deadline: u128,
    pub sqrt_price_limit_x96: u128,
}

pub struct ISwapRouter;
impl ISwapRouter {
    fn exact_input_single(&self, _p: ExactInputSingleParams) -> u128 { 0 }
}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn swap(amount_in: u128, user_min_out: u128, user_deadline: u128, router: ISwapRouter) {
        let params = ExactInputSingleParams {
            amount_in,
            amount_out_minimum: user_min_out,
            deadline: user_deadline,
            sqrt_price_limit_x96: 0,
        };
        router.exact_input_single(params);
    }
}
