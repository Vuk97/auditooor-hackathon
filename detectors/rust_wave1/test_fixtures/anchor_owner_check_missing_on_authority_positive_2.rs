// POSITIVE: admin field as UncheckedAccount without constraint
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct AdminAction<'info> {
    #[account(mut)]
    pub treasury: Account<'info, Treasury>,
    // BAD: admin declared as UncheckedAccount without has_one or constraint
    #[account(mut)]
    pub admin: UncheckedAccount<'info>,
}

#[account]
pub struct Treasury {
    pub admin: Pubkey,
    pub balance: u64,
}

pub fn drain_treasury(ctx: Context<AdminAction>) -> Result<()> {
    let balance = ctx.accounts.treasury.balance;
    ctx.accounts.treasury.balance = 0;
    // Attacker can pass any admin pubkey and drain treasury
    Ok(())
}
