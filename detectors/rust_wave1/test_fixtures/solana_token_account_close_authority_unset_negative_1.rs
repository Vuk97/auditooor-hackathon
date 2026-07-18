// NEGATIVE: initialize_account followed by set_authority(CloseAccount) — safe
use solana_program::program::invoke;
use spl_token::instruction::{initialize_account, set_authority, AuthorityType};

pub fn create_token_account_safe(
    accounts: &[AccountInfo],
    mint: &Pubkey,
    owner: &Pubkey,
    close_authority: &Pubkey,
) -> ProgramResult {
    let ix = initialize_account(
        &spl_token::id(),
        accounts[0].key,
        mint,
        owner,
    )?;
    invoke(&ix, accounts)?;

    // SAFE: explicitly set close authority
    let set_auth_ix = set_authority(
        &spl_token::id(),
        accounts[0].key,
        Some(close_authority),
        AuthorityType::CloseAccount,
        owner,
        &[],
    )?;
    invoke(&set_auth_ix, accounts)?;
    Ok(())
}
