// POSITIVE: try_to_vec() result discarded with let _ =
use anchor_lang::prelude::*;
use borsh::BorshSerialize;

#[program]
pub mod state_save {
    use super::*;

    pub fn save_state(ctx: Context<SaveCtx>, value: u64) -> Result<()> {
        let state = ctx.accounts.my_state.clone();

        // BAD: serialization result discarded — failure goes undetected
        let _ = state.try_to_vec();

        ctx.accounts.my_state.value = value;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SaveCtx<'info> {
    #[account(mut)]
    pub my_state: Account<'info, MyState>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(BorshSerialize)]
pub struct MyState {
    pub value: u64,
    pub data: Vec<u8>,
}
