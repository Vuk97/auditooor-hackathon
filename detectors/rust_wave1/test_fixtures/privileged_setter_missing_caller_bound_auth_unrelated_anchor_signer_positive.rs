use anchor_lang::prelude::*;

#[account]
pub struct ConfigState {
    pub admin: Pubkey,
    pub fee_bps: u64,
}

#[derive(Accounts)]
pub struct SetProgramConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, ConfigState>,
    pub payer: Signer<'info>,
}

pub fn set_config(ctx: Context<SetProgramConfig>, new_admin: Pubkey, fee_bps: u64) -> Result<()> {
    let _payer = &ctx.accounts.payer;
    ctx.accounts.config.admin = new_admin;
    ctx.accounts.config.fee_bps = fee_bps;
    Ok(())
}
