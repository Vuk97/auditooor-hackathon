// POSITIVE: token::transfer called after mutating account.amount (CEI violation)
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Transfer, Token};

#[program]
pub mod pool_vulnerable {
    use super::*;

    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
        let rewards = ctx.accounts.user_state.pending_rewards;
        // BAD: clear pending rewards BEFORE the CPI transfer
        ctx.accounts.user_state.pending_rewards = 0;

        // CPI — state already mutated; reentrancy here sees pending_rewards=0
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.reward_vault.to_account_info(),
                    to: ctx.accounts.user_token.to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                },
            ),
            rewards,
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    #[account(mut)]
    pub user_state: Account<'info, UserState>,
    #[account(mut)]
    pub reward_vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    pub vault_authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct UserState {
    pub pending_rewards: u64,
}
