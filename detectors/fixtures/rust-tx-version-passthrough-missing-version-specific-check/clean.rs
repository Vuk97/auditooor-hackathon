// clean.rs — should NOT trigger: verify_v6_transaction adds V6-specific
// network upgrade validation before delegating.
use std::sync::Arc;

struct Verifier;
struct Request;
struct Network;
struct NetworkUpgrade;
struct Transaction;
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

    fn verify_v6_transaction_network_upgrade(
        transaction: &Transaction,
        network_upgrade: NetworkUpgrade,
    ) -> Result<(), TransactionError> {
        Ok(())
    }

    /// V6 adds a network-upgrade check before delegating - this is safe.
    #[cfg(all(zcash_unstable = "nu7", feature = "tx_v6"))]
    fn verify_v6_transaction(
        request: &Request,
        network: &Network,
        script_verifier: ScriptVerifier,
        cached_ffi_transaction: Arc<CachedFfiTransaction>,
    ) -> Result<AsyncChecks, TransactionError> {
        // V6-specific check: validate the network upgrade supports V6
        Self::verify_v6_transaction_network_upgrade(
            &Transaction,
            NetworkUpgrade,
        )?;
        Self::verify_v5_transaction(request, network, script_verifier, cached_ffi_transaction)
    }
}
