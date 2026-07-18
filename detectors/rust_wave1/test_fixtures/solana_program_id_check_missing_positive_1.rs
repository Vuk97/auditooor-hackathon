// POSITIVE: AccountInfo data borrowed without owner check
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};

pub fn process_oracle_price(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let oracle_account = next_account_info(account_iter)?;

    // BAD: no check that oracle_account.owner == expected_oracle_program_id
    // Attacker can pass an account owned by a malicious program
    let data = oracle_account.try_borrow_data()?;
    let price = u64::from_le_bytes(data[0..8].try_into().unwrap());

    // Use crafted price from attacker-controlled oracle
    msg!("Oracle price: {}", price);
    Ok(())
}
