use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod proxy_delegate_target_hijack_positive {
    use super::*;

    pub fn initialize_proxy(
        ctx: Context<InitializeProxy>,
        implementation_hash: [u8; 32],
        delegate_target: Pubkey,
    ) -> Result<()> {
        let proxy = &mut ctx.accounts.proxy_state;

        if proxy.initialized {
            return err!(ProxyError::AlreadyInitialized);
        }

        proxy.implementation_hash = implementation_hash;
        proxy.delegate_target = delegate_target;
        proxy.initialized = true;
        Ok(())
    }

    pub fn dispatch(ctx: Context<Dispatch>, calldata: Vec<u8>) -> Result<()> {
        let proxy = &ctx.accounts.proxy_state;
        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: proxy.delegate_target,
            accounts: vec![],
            data: calldata,
        };
        anchor_lang::solana_program::program::invoke_signed(
            &ix,
            &[],
            &[&[b"proxy", &[ctx.bumps.proxy_state]]],
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeProxy<'info> {
    #[account(init, payer = payer, space = 8 + 128)]
    pub proxy_state: Account<'info, ProxyState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Dispatch<'info> {
    #[account(mut)]
    pub proxy_state: Account<'info, ProxyState>,
}

#[account]
pub struct ProxyState {
    pub implementation_hash: [u8; 32],
    pub delegate_target: Pubkey,
    pub initialized: bool,
}

#[error_code]
pub enum ProxyError {
    AlreadyInitialized,
}
