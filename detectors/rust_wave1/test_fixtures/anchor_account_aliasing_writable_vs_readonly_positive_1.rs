// POSITIVE: #[account(mut)] on AccountInfo without constraint — aliasing risk
use anchor_lang::prelude::*;

#[program]
pub mod alias_vuln {
    use super::*;

    pub fn transfer_tokens(ctx: Context<TransferCtx>, amount: u64) -> Result<()> {
        // Attacker can pass same pubkey for source and destination
        let source_lamports = ctx.accounts.source.lamports();
        **ctx.accounts.source.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferCtx<'info> {
    #[account(mut)]
    pub source: AccountInfo<'info>,      // BAD: AccountInfo without constraint
    #[account(mut)]
    pub destination: AccountInfo<'info>, // BAD: no check that source != destination
    pub payer: Signer<'info>,
}
