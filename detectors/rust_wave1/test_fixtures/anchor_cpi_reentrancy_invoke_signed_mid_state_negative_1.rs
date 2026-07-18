// NEGATIVE: CPI happens BEFORE state mutation (correct CEI order)
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Transfer, Token};

#[program]
pub mod safe_pool {
    use super::*;

    pub fn withdraw_safe(ctx: Context<WithdrawSafe>, amount: u64) -> Result<()> {
        // GOOD: CPI first (Checks-Effects-Interactions: Interactions before Effects
        // is wrong naming but in Solana CEI means: check, then CPI, then write)
        // Correct: do all checks, then external calls, then state writes
        require!(ctx.accounts.vault.balance >= amount, VaultError::InsufficientFunds);

        // CPI transfer first
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault_token.to_account_info(),
                    to: ctx.accounts.user_token.to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                },
            ),
            amount,
        )?;

        // State write AFTER CPI — safe
        ctx.accounts.vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawSafe<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    pub vault_authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct VaultState {
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    InsufficientFunds,
}
