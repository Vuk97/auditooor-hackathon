// Mock Anchor handler — declares Signer<'info> for authority

pub struct UpdateCtx<'info> {
    pub authority: Signer<'info>,
    pub state: AccountInfo<'info>,
}

pub fn update_params(ctx: UpdateCtx, new_rate: i128) {
    let authority = ctx.authority;
    ctx.state.set(new_rate);
    token::transfer(authority, new_rate);
}

pub struct Signer<'info> {
    _p: &'info (),
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
