// NEGATIVE: try_to_vec() propagated with ? — safe
use anchor_lang::prelude::*;
use borsh::BorshSerialize;

#[program]
pub mod safe_serialize {
    use super::*;

    pub fn save_safe(ctx: Context<SaveSafe>, value: u64) -> Result<()> {
        let state = MyState { value, data: vec![0u8; 8] };

        // SAFE: ? propagates serialization error
        let bytes = state.try_to_vec()?;
        msg!("Serialized {} bytes", bytes.len());

        ctx.accounts.my_state.value = value;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SaveSafe<'info> {
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
