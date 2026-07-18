use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Token;
impl Token {
    fn balance_of(&self, _who: Address) -> u128 { 1_000_000 }
}
pub struct Env;
impl Env {
    fn current_contract(&self) -> Address { [0; 20] }
}
fn load_token() -> Token { Token }
fn load_total_shares() -> u128 { 100_000 }
fn save_user_shares(_who: Address, _s: u128) {}
#[contract]
pub struct RebasingVault;
#[contractimpl]
impl RebasingVault {
    // BUG: shares = amount * total_shares / balance_of(self) — rebasing denominator
    pub fn deposit(env: Env, user: Address, amount: u128) {
        let token = load_token();
        let total_shares = load_total_shares();
        let self_addr = env.current_contract();
        let shares = amount * total_shares / token.balance_of(self_addr);
        save_user_shares(user, shares);
    }
}
