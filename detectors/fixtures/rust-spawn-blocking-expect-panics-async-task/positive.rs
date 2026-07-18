// positive.rs — should fire: spawn_blocking with inner .expect() + outer .await.expect()

use std::sync::Arc;

struct Network;
struct Template;

impl Template {
    fn new_coinbase(_net: &Network, _height: u32) -> Result<Template, String> {
        Ok(Template)
    }
}

// Direct form: spawn_blocking(...).await.expect(...)
async fn get_block_template_direct(network: Arc<Network>, height: u32) -> Template {
    tokio::task::spawn_blocking(move || {
        Template::new_coinbase(&network, height)
            .expect("valid coinbase tx")
    })
    .await
    .expect("valid coinbase tx")
}

// Indirect form: closure variable, then .await.expect()
async fn get_block_template_indirect(network: Arc<Network>, height: u32) -> Template {
    let precompute = |net: Arc<Network>, h: u32| {
        tokio::task::spawn_blocking(move || {
            Template::new_coinbase(&net, h).expect("valid coinbase tx")
        })
    };

    precompute(network, height)
        .await
        .expect("valid coinbase tx")
}
