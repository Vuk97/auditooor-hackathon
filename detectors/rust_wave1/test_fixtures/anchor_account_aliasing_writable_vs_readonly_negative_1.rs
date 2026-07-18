// NEGATIVE: AccountInfo with /// CHECK: marker — developer acknowledged
use anchor_lang::prelude::*;

#[program]
pub mod safe_transfer {
    use super::*;

    pub fn do_transfer(ctx: Context<SafeTransfer>, amount: u64) -> Result<()> {
        require!(
            ctx.accounts.source.key() != ctx.accounts.destination.key(),
            TransferError::SameAccount
        );
        **ctx.accounts.source.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SafeTransfer<'info> {
    /// CHECK: source is validated by key inequality check in instruction
    #[account(mut)]
    pub source: AccountInfo<'info>,
    /// CHECK: destination is validated by key inequality check in instruction
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[error_code]
pub enum TransferError {
    SameAccount,
}
