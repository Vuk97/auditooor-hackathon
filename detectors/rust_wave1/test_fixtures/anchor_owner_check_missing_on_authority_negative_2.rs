// NEGATIVE: authority field constrained via has_one — safe
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ConstrainedUpdate<'info> {
    // SAFE: has_one = authority enforces that pool.authority == authority.key()
    #[account(mut, has_one = authority @ PoolError::InvalidAuthority)]
    pub pool: Account<'info, PoolState>,
    pub authority: Signer<'info>,
}

#[account]
pub struct PoolState {
    pub fee_rate: u64,
    pub authority: Pubkey,
}

pub fn set_fee(ctx: Context<ConstrainedUpdate>, fee: u64) -> Result<()> {
    ctx.accounts.pool.fee_rate = fee;
    Ok(())
}

#[error_code]
pub enum PoolError {
    InvalidAuthority,
}
