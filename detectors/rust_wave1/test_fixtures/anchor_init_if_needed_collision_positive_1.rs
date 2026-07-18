// POSITIVE: init_if_needed without re-init guard — race condition
use anchor_lang::prelude::*;

#[program]
pub mod registry {
    use super::*;

    pub fn register_user(ctx: Context<RegisterUser>, name: String) -> Result<()> {
        // BAD: init_if_needed means this can be called multiple times
        // Attacker front-runs legitimate user, sets attacker-controlled data
        ctx.accounts.user_record.name = name;
        ctx.accounts.user_record.owner = ctx.accounts.user.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RegisterUser<'info> {
    #[account(
        init_if_needed,
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
