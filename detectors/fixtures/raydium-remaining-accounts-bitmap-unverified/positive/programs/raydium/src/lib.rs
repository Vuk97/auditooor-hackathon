use anchor_lang::prelude::*;

#[program]
pub mod raydium {
    use super::*;

    pub fn increase_liquidity(ctx: Context<IncreaseLiquidity>) -> Result<()> {
        let bitmap_info = ctx.remaining_accounts.get(0).unwrap();
        let bitmap_extension =
            TickArrayBitmapExtension::try_deserialize(&mut &bitmap_info.data.borrow()[..])?;
        let _ = bitmap_extension.pool_id;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct IncreaseLiquidity<'info> {
    pub pool_state: Account<'info, PoolState>,
}

#[account]
pub struct PoolState {
    pub pool_id: Pubkey,
}

#[account]
pub struct TickArrayBitmapExtension {
    pub pool_id: Pubkey,
}
