// positive.rs — SHOULD fire: check_maturity_height is guarded behind
// is_mempool() with no else branch, so the block-inclusion path skips it.

use std::pin::Pin;
use std::future::Future;

struct Network;
struct Request;
struct Utxo;
struct TransactionError;
struct Verifier;

impl Request {
    fn is_mempool(&self) -> bool { false }
}

impl Verifier {
    fn check_maturity_height(
        _network: &Network,
        _req: &Request,
        _utxos: &std::collections::HashMap<u32, Utxo>,
    ) -> Result<(), TransactionError> {
        Ok(())
    }
}

// Mirrors the real zebra `fn call()` shape: non-async fn returning a Future,
// containing an `async move { ... }` block.
fn call(req: Request) -> Pin<Box<dyn Future<Output = Result<(), TransactionError>> + Send>> {
    let network = Network;
    let utxos = std::collections::HashMap::new();
    Box::pin(async move {
        // Maturity check is only for mempool path — block path silently skips it.
        if req.is_mempool() {
            Verifier::check_maturity_height(&network, &req, &utxos)?;
        }
        // ... rest of validation continues without maturity check for block path
        Ok(())
    })
}
