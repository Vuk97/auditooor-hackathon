// positive.rs — should fire: block-level verifier call() invokes
// coinbase_outputs_are_decryptable and also delegates to transaction_verifier.
// This mirrors the real zebra-consensus shape in block.rs Verifier::call.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

struct BlockVerifier<V> {
    transaction_verifier: V,
    network: Network,
}

struct Network;
struct Request;
struct Response;
struct Error;
struct Transaction;

mod tx {
    pub mod check {
        use super::super::*;
        pub fn coinbase_outputs_are_decryptable(
            coinbase_tx: &Transaction,
            _network: &Network,
            _height: u32,
        ) -> Result<(), Error> {
            Ok(())
        }
    }
    pub enum Request {
        Block {
            transaction: Transaction,
        },
    }
}

impl<V> tower::Service<Request> for BlockVerifier<V>
where
    V: tower::Service<tx::Request>,
{
    type Response = Response;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let network = Network;
        let transaction_verifier = &self.transaction_verifier;
        Box::pin(async move {
            let coinbase_tx = Transaction;
            let height = 100u32;

            // ZIP-212: check shielded coinbase output decryptability at block level
            tx::check::coinbase_outputs_are_decryptable(&coinbase_tx, &network, height)
                .expect("coinbase outputs must be decryptable");

            // Delegate per-transaction checks to the inner transaction verifier
            // This block-level call dispatches tx::Request::Block items
            // transaction_verifier.call(tx::Request::Block { transaction: coinbase_tx });

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
