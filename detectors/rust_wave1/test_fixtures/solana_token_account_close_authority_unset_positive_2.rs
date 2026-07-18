// POSITIVE: Token account init in Anchor context without close authority setup
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount, Mint};

#[program]
pub mod vault {
    use super::*;

    pub fn create_vault(ctx: Context<CreateVault>) -> Result<()> {
        // initialize_account called implicitly by #[account(init, token::*)]
        // No set_authority for CloseAccount — anyone with mint authority can close
        let _vault_key = ctx.accounts.vault_token.key();
        // Missing: cpi to set_authority(AuthorityType::CloseAccount, ...)
        let ix = spl_token::instruction::initialize_account(
            &spl_token::ID,
            ctx.accounts.vault_token.to_account_info().key,
            ctx.accounts.mint.to_account_info().key,
            ctx.accounts.vault_authority.key,
        )?;
        anchor_lang::solana_program::program::invoke_signed(
            &ix,
            &[
                ctx.accounts.vault_token.to_account_info(),
                ctx.accounts.mint.to_account_info(),
            ],
            &[],
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateVault<'info> {
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    /// CHECK: authority
    pub vault_authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
    pub payer: Signer<'info>,
}
