// NEGATIVE: reentrancy guard set before CPI — safe
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;

#[program]
pub mod guarded {
    use super::*;

    pub fn process_with_guard(ctx: Context<Guarded>, amount: u64) -> Result<()> {
        // Reentrancy guard check
        require!(!ctx.accounts.state.reentrancy_guard, GuardError::Reentrant);
        ctx.accounts.state.reentrancy_guard = true;

        // State mutation is safe after guard is set
        ctx.accounts.state.balance -= amount;

        let ix = anchor_lang::solana_program::system_instruction::transfer(
            ctx.accounts.state.to_account_info().key,
            ctx.accounts.recipient.key,
            amount,
        );
        invoke_signed(
            &ix,
            &[ctx.accounts.state.to_account_info(), ctx.accounts.recipient.clone()],
            &[&[b"state", &[ctx.bumps.state]]],
        )?;

        ctx.accounts.state.reentrancy_guard = false;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Guarded<'info> {
    #[account(mut, seeds = [b"state"], bump)]
    pub state: Account<'info, StateAccount>,
    /// CHECK: recipient
    pub recipient: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct StateAccount {
    pub balance: u64,
    pub reentrancy_guard: bool,
}

#[error_code]
pub enum GuardError {
    Reentrant,
}
