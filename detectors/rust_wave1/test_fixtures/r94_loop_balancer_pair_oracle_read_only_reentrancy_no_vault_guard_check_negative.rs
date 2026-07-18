use soroban_sdk::{contract, contractimpl};

pub struct Vault;
impl Vault {
    fn manage_user_balance(&self, _ops: &[u8]) {}
    fn get_pool_tokens(&self, _id: u64) -> (Vec<[u8; 20]>, Vec<u128>) {
        (Vec::new(), vec![100, 200])
    }
}

fn load_vault(_a: [u8; 20]) -> Vault {
    Vault
}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn get_price(vault_addr: [u8; 20], pool_id: u64) -> u128 {
        let balancer_vault = load_vault(vault_addr);
        balancer_vault.manage_user_balance(&[]);
        let (_tokens, balances) = balancer_vault.get_pool_tokens(pool_id);
        balances[0]
    }
}
