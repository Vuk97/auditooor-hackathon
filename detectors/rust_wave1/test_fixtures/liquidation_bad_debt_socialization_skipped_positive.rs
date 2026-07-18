use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: bad-debt branch exists but no socialization / treasury call
    pub fn liquidate(env: Env, borrower: Address, debt: i128, collateral: i128) -> i128 {
        if collateral < debt {
            // silently cap recovery at collateral
            return collateral;
        }
        debt
    }
}
