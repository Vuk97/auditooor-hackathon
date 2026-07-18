// Mock Anchor attribute fixture (won't compile, text-matched)

#[derive(Accounts)]
pub struct BadCtx<'info> {
    // VULN: empty account() attr, no seeds / mut / constraint
    #[account()]
    pub pool_config: Account<'info, PoolConfig>,

    // VULN: attr with only `init` — no seeds binding
    #[account(init)]
    pub user_state: Account<'info, UserState>,
}

pub struct PoolConfig {}
pub struct UserState {}
