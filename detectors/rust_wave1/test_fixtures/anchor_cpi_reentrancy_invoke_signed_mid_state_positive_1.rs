// POSITIVE: state mutation BEFORE invoke_signed — CPI reentrancy
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;

#[program]
pub mod vulnerable {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // BAD: decrement balance BEFORE external call
        ctx.accounts.vault.balance -= amount;

        // CPI to user-supplied program (reentrancy vector)
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            ctx.accounts.vault.to_account_info().key,
            ctx.accounts.recipient.key,
            amount,
        );
        invoke_signed(
            &ix,
            &[ctx.accounts.vault.to_account_info(), ctx.accounts.recipient.clone()],
            &[&[b"vault", &[ctx.bumps.vault]]],
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, VaultState>,
    /// CHECK: recipient supplied by caller
    pub recipient: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct VaultState {
    pub balance: u64,
}
