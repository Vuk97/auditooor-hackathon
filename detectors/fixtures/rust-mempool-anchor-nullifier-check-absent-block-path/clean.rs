// clean.rs — should NOT fire: anchor/nullifier check is unconditional
// (applies to both mempool and block transactions)

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

struct State;
struct Request;
struct UnminedTxWithOutputs;

impl Request {
    fn mempool_transaction(&self) -> Option<UnminedTxWithOutputs> { None }
    fn block_time(&self) -> Option<u64> { None }
    fn as_unmined(&self) -> UnminedTxWithOutputs { UnminedTxWithOutputs }
}

enum Response { Block { tx_id: u64 }, Mempool { tx: UnminedTxWithOutputs } }

impl Service<Request> for Verifier<State> {
    type Response = Response;
    type Error = ();
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let state = self.state.clone();
        Box::pin(async move {
            // Block-specific branch
            if let Some(_bt) = req.block_time() {
                check_lock_time();
            }

            // FIXED: anchor/nullifier check runs unconditionally for both
            // mempool and block transactions.
            let tx_for_check = req.as_unmined();
            let _ = state.oneshot(
                zs::Request::CheckBestChainTipNullifiersAndAnchors(tx_for_check)
            ).await;

            // Then branch on request type for the response
            match req {
                Request::Block { .. } => Ok(Response::Block { tx_id: 0 }),
                _ => Ok(Response::Block { tx_id: 1 }),
            }
        })
    }
}
