// NEGATIVE: init_if_needed with explicit is_initialized guard — safe
use anchor_lang::prelude::*;

#[program]
pub mod guarded_registry {
    use super::*;

    pub fn register_or_update(ctx: Context<RegisterOrUpdate>, name: String) -> Result<()> {
        // SAFE: explicit guard prevents re-initialization attack
        if ctx.accounts.user_record.is_initialized {
            // Already initialized — only update non-critical fields
            require!(
                ctx.accounts.user_record.owner == ctx.accounts.user.key(),
                RegistryError::NotOwner
            );
        }
        ctx.accounts.user_record.name = name;
        ctx.accounts.user_record.is_initialized = true;
        ctx.accounts.user_record.owner = ctx.accounts.user.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RegisterOrUpdate<'info> {
    #[account(
        init_if_needed,
        payer = user,
        space = 8 + 32 + 64 + 1,
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
    pub is_initialized: bool,
}

#[error_code]
pub enum RegistryError {
    NotOwner,
}
