// Mock Anchor attribute fixture with valid constraints

#[derive(Accounts)]
pub struct GoodCtx<'info> {
    // SAFE: seeds + bump binding
    #[account(seeds = [b"pool", authority.key().as_ref()], bump)]
    pub pool_config: Account<'info, PoolConfig>,

    // SAFE: mut
    #[account(mut)]
    pub user_state: Account<'info, UserState>,

    // SAFE: has_one
    #[account(has_one = authority)]
    pub vault: Account<'info, Vault>,
}

pub struct PoolConfig {}
pub struct UserState {}
pub struct Vault {}
