use soroban_sdk::{contract, contractimpl};
pub struct Ctx { pub version: String }
pub struct App;
impl App { pub fn on_chan_open_init(&self, _c: &Ctx) -> String { String::new() } }
#[contract]
pub struct Middleware;
#[contractimpl]
impl Middleware {
    // BUG: invokes app.on_chan_open_init (which negotiates) but returns caller's version
    pub fn on_chan_open_init(ctx: Ctx, version: String, app: App) -> Result<String, ()> {
        let _negotiated = app.on_chan_open_init(&ctx);
        Ok(version)
    }
}
