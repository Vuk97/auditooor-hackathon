use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod proxy_delegate_target_hijack_negative {
    use super::*;

    pub fn initialize_proxy(
        ctx: Context<InitializeProxy>,
        implementation_hash: [u8; 32],
        delegate_target: Pubkey,
    ) -> Result<()> {
        let proxy = &mut ctx.accounts.proxy_state;

        require_keys_eq!(
            ctx.accounts.configured_admin.key(),
            ctx.accounts.expected_admin.key(),
            ProxyError::WrongAdmin
        );
        require!(
            ctx.accounts
                .implementation_registry
                .approved_implementations
                .contains(&delegate_target),
            ProxyError::UnapprovedImplementation
        );
        require!(
            ctx.accounts
                .implementation_registry
                .approved_code_hashes
                .contains(&implementation_hash),
            ProxyError::UnapprovedImplementation
        );

        proxy.implementation_hash = implementation_hash;
        proxy.delegate_target = delegate_target;
        proxy.initialized = true;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeProxy<'info> {
    #[account(init, payer = payer, space = 8 + 128)]
    pub proxy_state: Account<'info, ProxyState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub configured_admin: Signer<'info>,
    pub expected_admin: Signer<'info>,
    pub implementation_registry: Account<'info, ImplementationRegistry>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct ProxyState {
    pub implementation_hash: [u8; 32],
    pub delegate_target: Pubkey,
    pub initialized: bool,
}

#[account]
pub struct ImplementationRegistry {
    pub approved_implementations: Vec<Pubkey>,
    pub approved_code_hashes: Vec<[u8; 32]>,
}

#[error_code]
pub enum ProxyError {
    WrongAdmin,
    UnapprovedImplementation,
}
