// positive.rs — should trigger: verify_v6_transaction is a pure passthrough
// to verify_v5_transaction with no V6-specific checks.
use std::sync::Arc;

struct Verifier;
struct Request;
struct Network;
struct ScriptVerifier;
struct CachedFfiTransaction;
struct AsyncChecks;
struct TransactionError;

impl Verifier {
    fn verify_v5_transaction(
        request: &Request,
        network: &Network,
        script_verifier: ScriptVerifier,
        cached_ffi_transaction: Arc<CachedFfiTransaction>,
    ) -> Result<AsyncChecks, TransactionError> {
        Ok(AsyncChecks)
    }

    /// Passthrough to verify_v5_transaction, but for V6 transactions.
    #[cfg(all(zcash_unstable = "nu7", feature = "tx_v6"))]
    fn verify_v6_transaction(
        request: &Request,
        network: &Network,
        script_verifier: ScriptVerifier,
        cached_ffi_transaction: Arc<CachedFfiTransaction>,
    ) -> Result<AsyncChecks, TransactionError> {
        Self::verify_v5_transaction(request, network, script_verifier, cached_ffi_transaction)
    }
}
