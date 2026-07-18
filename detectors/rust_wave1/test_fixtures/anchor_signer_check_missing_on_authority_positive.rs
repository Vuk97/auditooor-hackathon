// Mock Anchor handler — no is_signer check

pub struct UpdateCtx<'info> {
    pub authority: AccountInfo<'info>,
    pub state: AccountInfo<'info>,
}

pub fn update_params(ctx: UpdateCtx, new_rate: i128) {
    // VULN: uses `authority` but never checks is_signer or key match
    let authority = ctx.authority;
    ctx.state.set(new_rate);
    token::transfer(authority, new_rate);
}

pub struct AccountInfo<'info> {
    _p: &'info (),
}

impl<'info> AccountInfo<'info> {
    pub fn set(&self, _: i128) {}
}

mod token {
    pub fn transfer<T>(_: T, _: i128) {}
}
