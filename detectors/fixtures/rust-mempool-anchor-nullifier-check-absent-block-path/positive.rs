// positive.rs — should fire: anchor/nullifier check is mempool-only
// Mirrors the shape in zebra-consensus/src/transaction.rs Verifier::call

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

struct State;
struct Request;
struct Response;
struct Error;
struct UnminedTx;

impl Request {
    fn mempool_transaction(&self) -> Option<UnminedTx> { None }
    fn block_time(&self) -> Option<u64> { None }
}

enum Response { Block { tx_id: u64 }, Mempool { tx: UnminedTx } }

impl Service<Request> for Verifier<State> {
    type Response = Response;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let state = self.state.clone();
        Box::pin(async move {
            // Some shared checks here
            check_basic(&req);

            // Block-specific branch
            if let Some(_bt) = req.block_time() {
                check_lock_time();
            }

            // *** ASYMMETRY: only the mempool path gets the anchor/nullifier check ***
            if let Some(unmined_tx) = req.mempool_transaction() {
                let _ = state.oneshot(
                    zs::Request::CheckBestChainTipNullifiersAndAnchors(unmined_tx)
                ).await;
            }
            // Block path: no CheckBestChainTipNullifiersAndAnchors call

            Ok(Response::Block { tx_id: 0 })
        })
    }
}
