use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Token;
impl Token {
    fn balance_of(&self, _who: Address) -> u128 { 1_000_000 }
}
fn load_token() -> Token { Token }
fn load_total_shares() -> u128 { 100_000 }
fn tracked_balance() -> u128 { 800_000 }
fn save_user_shares(_who: Address, _s: u128) {}
#[contract]
pub struct RebasingVault;
#[contractimpl]
impl RebasingVault {
    // SAFE: uses tracked_balance() instead of balance_of(self) as denominator
    pub fn deposit(user: Address, amount: u128) {
        let _ignored_token = load_token();
        let total_shares = load_total_shares();
        let denom = tracked_balance();
        let shares = amount * total_shares / denom;
        save_user_shares(user, shares);
    }
}
