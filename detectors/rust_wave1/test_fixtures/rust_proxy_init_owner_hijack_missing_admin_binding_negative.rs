use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod proxy_init_owner_hijack_negative {
    use super::*;

    pub fn initialize_proxy(
        ctx: Context<InitializeProxy>,
        implementation_hash: [u8; 32],
        expected_admin: Pubkey,
    ) -> Result<()> {
        let proxy = &mut ctx.accounts.proxy_state;
        require!(!proxy.initialized, ProxyError::AlreadyInitialized);
        require_keys_eq!(ctx.accounts.configured_admin.key(), expected_admin);

        proxy.implementation_hash = implementation_hash;
        proxy.proxy_admin = ctx.accounts.configured_admin.key();
        proxy.initialized = true;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeProxy<'info> {
    #[account(init, payer = payer, space = 8 + 96)]
    pub proxy_state: Account<'info, ProxyState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub configured_admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct ProxyState {
    pub implementation_hash: [u8; 32],
    pub proxy_admin: Pubkey,
    pub initialized: bool,
}

#[error_code]
pub enum ProxyError {
    AlreadyInitialized,
}
