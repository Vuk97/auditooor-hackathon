// POSITIVE: initialize_account called without subsequent set_authority(CloseAccount)
use solana_program::program::invoke;
use spl_token::instruction::{initialize_account, AuthorityType};

pub fn create_token_account(
    accounts: &[AccountInfo],
    mint: &Pubkey,
    owner: &Pubkey,
) -> ProgramResult {
    // BAD: initialize_account does not set close_authority
    // Any holder of the default authority (mint authority) can close this account
    let ix = initialize_account(
        &spl_token::id(),
        accounts[0].key,
        mint,
        owner,
    )?;
    invoke(&ix, accounts)?;
    // Missing: set_authority(CloseAccount, Some(dedicated_close_authority))
    Ok(())
}
