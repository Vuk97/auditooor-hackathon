use anchor_lang::prelude::*;

#[account]
pub struct ConfigState {
    pub admin: Pubkey,
}

#[derive(Accounts)]
pub struct SetProgramConfig<'info> {
    #[account(mut, signer)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub config: Account<'info, ConfigState>,
}

pub fn set_config(ctx: Context<SetProgramConfig>, new_admin: Pubkey) -> Result<()> {
    ctx.accounts.config.admin = new_admin;
    Ok(())
}
