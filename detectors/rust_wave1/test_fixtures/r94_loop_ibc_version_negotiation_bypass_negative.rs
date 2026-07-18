use soroban_sdk::{contract, contractimpl};
pub struct Ctx { pub version: String }
pub struct App;
impl App { pub fn on_chan_open_init(&self, _c: &Ctx) -> String { String::new() } }
#[contract]
pub struct SafeMiddleware;
#[contractimpl]
impl SafeMiddleware {
    // OK: returns the negotiated_version from underlying app
    pub fn on_chan_open_init(ctx: Ctx, _version: String, app: App) -> Result<String, ()> {
        let negotiated_version = app.on_chan_open_init(&ctx);
        Ok(negotiated_version)
    }
}
