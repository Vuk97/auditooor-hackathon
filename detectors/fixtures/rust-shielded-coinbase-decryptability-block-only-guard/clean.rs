// clean.rs — should NOT fire: transaction-level verifier call() does NOT
// call coinbase_outputs_are_decryptable (this is the inner verifier shape).
// Also: a block verifier that does not delegate to a transaction_verifier.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

struct Network;
struct Request;
struct Response;
struct Error;
struct Transaction;

mod check {
    use super::*;
    pub fn coinbase_outputs_are_decryptable(
        _tx: &Transaction,
        _network: &Network,
        _height: u32,
    ) -> Result<(), Error> {
        Ok(())
    }
}

// Case 1: transaction-verifier call() — no coinbase_outputs_are_decryptable
// call, no transaction_verifier delegation.
struct TxVerifier;

impl tower::Service<Request> for TxVerifier {
    type Response = Response;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request) -> Self::Future {
        Box::pin(async move {
            // Inner transaction verifier: performs various checks but
            // does NOT call coinbase_outputs_are_decryptable
            let _tx = Transaction;
            Ok(Response)
        })
    }
}

// Case 2: block verifier that calls the check but does NOT delegate to
// a transaction_verifier — also should not fire (no delegation signal)
struct StandaloneBlockVerifier;

impl tower::Service<Request> for StandaloneBlockVerifier {
    type Response = Response;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request) -> Self::Future {
        Box::pin(async move {
            let network = Network;
            let coinbase_tx = Transaction;
            // Calls coinbase_outputs_are_decryptable but has no
            // transaction_verifier delegation — should NOT fire
            check::coinbase_outputs_are_decryptable(&coinbase_tx, &network, 1)
                .expect("must be decryptable");
            Ok(Response)
        })
    }
}

mod tower {
    pub trait Service<Req> {
        type Response;
        type Error;
        type Future: std::future::Future;
        fn poll_ready(&mut self, cx: &mut std::task::Context<'_>)
            -> std::task::Poll<Result<(), Self::Error>>;
        fn call(&mut self, req: Req) -> Self::Future;
    }
}
