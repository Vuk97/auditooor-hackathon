// NEGATIVE: owner check performed before data borrow — safe
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

const ORACLE_PROGRAM_ID: Pubkey = solana_program::pubkey!("oRCLe111111111111111111111111111111111111111");

pub fn process_oracle_safe(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let oracle_account = next_account_info(account_iter)?;

    // SAFE: owner check BEFORE borrowing data
    if oracle_account.owner != &ORACLE_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let data = oracle_account.try_borrow_data()?;
    let price = u64::from_le_bytes(data[0..8].try_into().unwrap());
    msg!("Oracle price: {}", price);
    Ok(())
}
