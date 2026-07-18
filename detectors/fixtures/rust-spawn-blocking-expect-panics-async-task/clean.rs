// clean.rs — should NOT fire: safe variants

use std::sync::Arc;

struct Network;
struct Template;

impl Template {
    fn new_coinbase(_net: &Network, _height: u32) -> Result<Template, String> {
        Ok(Template)
    }
}

struct RpcError(String);

// Safe form 1: outer error is propagated with ? instead of .expect/.unwrap
async fn get_block_template_safe_q(
    network: Arc<Network>,
    height: u32,
) -> Result<Template, RpcError> {
    let result = tokio::task::spawn_blocking(move || {
        Template::new_coinbase(&network, height).expect("valid coinbase tx")
    })
    .await
    .map_err(|e| RpcError(format!("join error: {}", e)))?;
    Ok(result)
}

// Safe form 2: uses wait_for_panics() helper (Zebra mitigation)
async fn get_block_template_wait_for_panics(
    network: Arc<Network>,
    height: u32,
) -> Option<Template> {
    tokio::task::spawn_blocking(move || {
        Template::new_coinbase(&network, height).expect("valid coinbase tx")
    })
    .wait_for_panics()
    .await
}

// Safe form 3: inner Result returned, outer result matched (no .expect/.unwrap on JoinHandle)
async fn get_block_template_result(
    network: Arc<Network>,
    height: u32,
) -> Option<Template> {
    let join_result = tokio::task::spawn_blocking(move || {
        Template::new_coinbase(&network, height)
    })
    .await;
    match join_result {
        Ok(Ok(t)) => Some(t),
        _ => None,
    }
}

// Non-async fn with spawn_blocking + .expect should NOT fire (not async)
fn sync_spawn(network: Arc<Network>) {
    let handle = tokio::task::spawn_blocking(move || {
        Template::new_coinbase(&network, 0).expect("valid")
    });
    // No .await here - sync context, handle stored
    drop(handle);
}
