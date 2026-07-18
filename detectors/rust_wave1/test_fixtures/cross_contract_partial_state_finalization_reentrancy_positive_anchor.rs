use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;

pub fn settle_position(ctx: Context<SettlePosition>, shares: u64) -> Result<()> {
    let position = &mut ctx.accounts.position;
    position.pending_shares = shares;
    position.pending_status = 1;

    invoke_signed(
        &ctx.accounts.external_ix(),
        &ctx.accounts.to_account_infos(),
        &[],
    )?;

    position.total_shares = position.total_shares + shares;
    position.pending_status = 2;
    Ok(())
}

#[derive(Accounts)]
pub struct SettlePosition<'info> {
    #[account(mut)]
    pub position: Account<'info, PositionAccount>,
}

#[account]
pub struct PositionAccount {
    pub pending_shares: u64,
    pub pending_status: u8,
    pub total_shares: u64,
}
