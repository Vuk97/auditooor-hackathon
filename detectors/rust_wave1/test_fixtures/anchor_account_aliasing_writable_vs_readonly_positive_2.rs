// POSITIVE: alias via constraint = a.key() == b.key() with mut field
use anchor_lang::prelude::*;

#[program]
pub mod alias_constraint {
    use super::*;

    pub fn merge_accounts(ctx: Context<MergeCtx>) -> Result<()> {
        let balance = ctx.accounts.secondary.to_account_info().lamports();
        // Aliased write — secondary == primary here means double-credit
        **ctx.accounts.primary.try_borrow_mut_lamports()? += balance;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct MergeCtx<'info> {
    #[account(mut)]
    pub primary: Account<'info, UserAccount>,
    // BAD: constraint allows caller to pass primary == secondary
    #[account(constraint = secondary.key() == primary.key())]
    pub secondary: Account<'info, UserAccount>,
    pub authority: Signer<'info>,
}

#[account]
pub struct UserAccount {
    pub balance: u64,
}
