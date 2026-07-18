// SHOULD FIRE: per-actor cap map keyed on SocketAddr (composite: IP + port).
// Mirrors zebrad/src/components/mempool/downloads.rs:206 exactly.

use std::collections::HashMap;
use std::net::SocketAddr;

/// Maximum number of concurrent in-flight downloads per advertising peer.
/// Enforces the GHSA-4fc2 per-peer rate mitigation.
pub const MAX_INBOUND_CONCURRENCY_PER_PEER: usize = 5;

pub struct Downloads {
    /// The number of currently in-flight download tasks per advertising peer.
    ///
    /// Keyed on the peer's SocketAddr (IP + ephemeral port). Each TCP connection
    /// from the same attacker IP gets a distinct map entry because the ephemeral
    /// source port differs per connection.
    ///
    /// See `GHSA-4fc2-h7jh-287c`.
    pending_per_peer: HashMap<SocketAddr, usize>,
}

impl Downloads {
    pub fn new() -> Self {
        Downloads {
            pending_per_peer: HashMap::new(),
        }
    }

    pub fn check_and_increment_slot(&mut self, source: SocketAddr) -> bool {
        let count = self.pending_per_peer.get(&source).copied().unwrap_or(0);
        if count >= MAX_INBOUND_CONCURRENCY_PER_PEER {
            return false; // per-peer cap exceeded
        }
        *self.pending_per_peer.entry(source).or_insert(0) += 1;
        true
    }
}
