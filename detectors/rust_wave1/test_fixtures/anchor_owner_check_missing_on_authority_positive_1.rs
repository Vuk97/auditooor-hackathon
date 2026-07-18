// POSITIVE: authority field as AccountInfo without Signer or has_one
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, ConfigState>,
    // BAD: authority is AccountInfo, not Signer — anyone can pass any pubkey
    pub authority: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct ConfigState {
    pub fee_rate: u64,
    pub authority: Pubkey,
}

pub fn update_fee(ctx: Context<UpdateConfig>, new_fee: u64) -> Result<()> {
    // No signer check on authority — attacker passes arbitrary pubkey
    ctx.accounts.config.fee_rate = new_fee;
    Ok(())
}
