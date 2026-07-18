// clean.rs — should NOT fire: check_maturity_height is called on BOTH paths
// (either via an else branch or unconditionally outside the guard).

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

// Case 1: unconditional call — maturity is checked for all paths.
fn call_unconditional(req: Request) -> Pin<Box<dyn Future<Output = Result<(), TransactionError>> + Send>> {
    let network = Network;
    let utxos = std::collections::HashMap::new();
    Box::pin(async move {
        // Always check maturity regardless of request type.
        Verifier::check_maturity_height(&network, &req, &utxos)?;
        Ok(())
    })
}

// Case 2: if/else — both paths call the check.
fn call_if_else(req: Request) -> Pin<Box<dyn Future<Output = Result<(), TransactionError>> + Send>> {
    let network = Network;
    let utxos = std::collections::HashMap::new();
    Box::pin(async move {
        if req.is_mempool() {
            Verifier::check_maturity_height(&network, &req, &utxos)?;
        } else {
            // Block path also checks maturity.
            Verifier::check_maturity_height(&network, &req, &utxos)?;
        }
        Ok(())
    })
}

// Case 3: guarded but a DIFFERENT kind of check (not maturity) — should not fire.
fn call_non_maturity(req: Request) -> Pin<Box<dyn Future<Output = Result<(), TransactionError>> + Send>> {
    let network = Network;
    let utxos = std::collections::HashMap::new();
    Box::pin(async move {
        if req.is_mempool() {
            // Different check — not in the maturity family.
            let _ = (&network, &utxos);
            check_lock_time(&req)?;
        }
        Ok(())
    })
}

fn check_lock_time(_req: &Request) -> Result<(), TransactionError> {
    Ok(())
}
