use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct BridgeRouter;

#[contractimpl]
impl BridgeRouter {
    pub fn initiate_transfer(
        env: Env,
        native_asset: Address,
        recipient: Address,
        amount: i128,
        fee: i128,
        attached_value: i128,
    ) {
        let _ = attached_value;
        let forwarded = amount + fee;
        let native = token::Client::new(&env, &native_asset);
        native.transfer(&env.current_contract_address(), &recipient, &forwarded);
    }
}
