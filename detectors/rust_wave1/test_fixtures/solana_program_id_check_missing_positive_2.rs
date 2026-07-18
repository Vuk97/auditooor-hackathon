// POSITIVE: from_account_info called without owner check
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    program_pack::Pack,
};
use spl_token::state::Account as TokenAccount;

pub fn get_token_balance(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let token_account = next_account_info(account_iter)?;

    // BAD: from_account_info called without checking token_account.owner == spl_token::id()
    // Attacker creates an account with crafted data owned by a different program
    let token_state = TokenAccount::unpack(&token_account.try_borrow_data()?)?;
    msg!("Balance: {}", token_state.amount);
    Ok(())
}
