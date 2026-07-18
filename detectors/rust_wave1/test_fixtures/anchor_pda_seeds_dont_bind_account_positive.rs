// Mock Anchor — PDA seeds don't bind to any account.

#[derive(Accounts)]
pub struct BadCtx<'info> {
    // VULN: seeds only reference a bytestring literal, no .key()/.as_ref()
    #[account(seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
}

pub struct Vault {}
