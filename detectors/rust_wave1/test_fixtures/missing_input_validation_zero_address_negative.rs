use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: set_admin checks against Address::default() before storing.
    pub fn set_admin(env: Env, new_admin: Address) {
        if new_admin == Address::default() {
            panic!("zero addr");
        }
        env.storage().instance().set(&Symbol::new(&env, "admin"), &new_admin);
    }

    // OK: no address param.
    pub fn set_value(env: Env, amount: i128) {
        env.storage().instance().set(&Symbol::new(&env, "amount"), &amount);
    }

    // OK: require_auth on the address is treated as validation.
    pub fn set_ops(env: Env, operator: Address) {
        operator.require_auth();
        env.storage().instance().set(&Symbol::new(&env, "op"), &operator);
    }
}
