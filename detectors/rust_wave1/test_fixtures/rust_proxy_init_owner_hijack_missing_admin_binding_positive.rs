use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod proxy_init_owner_hijack_positive {
    use super::*;

    pub fn initialize_proxy(
        ctx: Context<InitializeProxy>,
        implementation_hash: [u8; 32],
    ) -> Result<()> {
        let proxy = &mut ctx.accounts.proxy_state;

        // BUG: the account paying for deployment becomes the upgrade admin.
        // No configured admin is passed or checked, so a front-running or
        // malicious factory caller owns future upgrades.
        proxy.implementation_hash = implementation_hash;
        proxy.proxy_admin = ctx.accounts.deployer.key();
        proxy.initialized = true;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeProxy<'info> {
    #[account(init, payer = deployer, space = 8 + 96)]
    pub proxy_state: Account<'info, ProxyState>,
    #[account(mut)]
    pub deployer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct ProxyState {
    pub implementation_hash: [u8; 32],
    pub proxy_admin: Pubkey,
    pub initialized: bool,
}
