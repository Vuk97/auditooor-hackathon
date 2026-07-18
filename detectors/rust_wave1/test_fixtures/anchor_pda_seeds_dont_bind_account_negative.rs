// Mock Anchor — PDA seeds bind to user.key()

#[derive(Accounts)]
pub struct GoodCtx<'info> {
    // SAFE: seeds include user.key().as_ref()
    #[account(seeds = [b"vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,

    pub user: Signer<'info>,
}

pub struct Vault {}
pub struct Signer<'info> {
    _p: &'info (),
}
