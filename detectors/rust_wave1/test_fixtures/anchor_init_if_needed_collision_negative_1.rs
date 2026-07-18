// NEGATIVE: init (not init_if_needed) — reverts if already initialized
use anchor_lang::prelude::*;

#[program]
pub mod registry_safe {
    use super::*;

    pub fn register_user_safe(ctx: Context<RegisterUserSafe>, name: String) -> Result<()> {
        ctx.accounts.user_record.name = name;
        ctx.accounts.user_record.owner = ctx.accounts.user.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RegisterUserSafe<'info> {
    // SAFE: init (not init_if_needed) — Anchor reverts if already exists
    #[account(
        init,
        payer = user,
        space = 8 + 32 + 64,
        seeds = [b"user", user.key().as_ref()],
        bump
    )]
    pub user_record: Account<'info, UserRecord>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct UserRecord {
    pub owner: Pubkey,
    pub name: String,
}
