// NEGATIVE: authority field is Signer<'info> — type-level check
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct SafeUpdate<'info> {
    #[account(mut, has_one = authority)]
    pub config: Account<'info, ConfigState>,
    // SAFE: Signer<'info> enforces signature at the runtime level
    pub authority: Signer<'info>,
}

#[account]
pub struct ConfigState {
    pub fee_rate: u64,
    pub authority: Pubkey,
}

pub fn update_fee_safe(ctx: Context<SafeUpdate>, new_fee: u64) -> Result<()> {
    ctx.accounts.config.fee_rate = new_fee;
    Ok(())
}
