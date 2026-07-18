// NEGATIVE: Strongly-typed Account<T> — Anchor enforces distinct owner/type
use anchor_lang::prelude::*;

#[program]
pub mod typed_accounts {
    use super::*;

    pub fn swap(ctx: Context<SwapCtx>, amount_in: u64) -> Result<()> {
        // Account<T> types ensure correct program ownership
        ctx.accounts.pool.token_a_reserve -= amount_in;
        ctx.accounts.pool.token_b_reserve += amount_in; // simplified
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SwapCtx<'info> {
    #[account(mut, has_one = authority)]
    pub pool: Account<'info, PoolState>,
    pub authority: Signer<'info>,
}

#[account]
pub struct PoolState {
    pub token_a_reserve: u64,
    pub token_b_reserve: u64,
    pub authority: Pubkey,
}
