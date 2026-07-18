// POSITIVE: init_if_needed on token escrow without initialization check
use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount, Mint};

#[program]
pub mod escrow {
    use super::*;

    pub fn deposit_to_escrow(ctx: Context<DepositEscrow>, amount: u64) -> Result<()> {
        // BAD: no check whether escrow was already initialized
        // Attacker can pre-create escrow with attacker as owner
        ctx.accounts.escrow.depositor = ctx.accounts.depositor.key();
        ctx.accounts.escrow.amount += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct DepositEscrow<'info> {
    #[account(
        init_if_needed,
        payer = depositor,
        space = 8 + 32 + 8,
        seeds = [b"escrow", depositor.key().as_ref()],
        bump
    )]
    pub escrow: Account<'info, EscrowState>,
    #[account(mut)]
    pub depositor: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct EscrowState {
    pub depositor: Pubkey,
    pub amount: u64,
}
