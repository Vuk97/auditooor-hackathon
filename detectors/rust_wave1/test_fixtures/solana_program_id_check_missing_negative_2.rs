// NEGATIVE: File has no AccountInfo parameters — no hit expected
use anchor_lang::prelude::*;

#[program]
pub mod simple_math {
    use super::*;

    pub fn add_values(ctx: Context<AddCtx>, a: u64, b: u64) -> Result<()> {
        ctx.accounts.result.value = a.checked_add(b)
            .ok_or(error!(MathError::Overflow))?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct AddCtx<'info> {
    #[account(mut)]
    pub result: Account<'info, ResultState>,
    pub authority: Signer<'info>,
}

#[account]
pub struct ResultState {
    pub value: u64,
}

#[error_code]
pub enum MathError {
    Overflow,
}
