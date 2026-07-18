// SHOULD NOT FIRE: per-actor cap map keyed on IpAddr (stable security identity).
// Mirrors the correct sibling pattern from
// zebrad/src/components/inbound/downloads.rs:131 (in_flight_ips: HashSet<IpAddr>).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

pub const MAX_INBOUND_CONCURRENCY_PER_IP: usize = 5;

pub struct BlockDownloads {
    /// Tracks in-flight download slots per advertiser IP.
    ///
    /// Keyed on IpAddr -- the stable security identity for a peer.
    /// All connections from the same attacker IP share one bucket, so
    /// opening N connections from one IP does NOT multiply the per-peer budget.
    in_flight_ips: HashSet<IpAddr>,

    /// General routing table: IpAddr-keyed is also correct for other rate maps.
    per_ip_count: HashMap<IpAddr, usize>,
}

impl BlockDownloads {
    pub fn new() -> Self {
        BlockDownloads {
            in_flight_ips: HashSet::new(),
            per_ip_count: HashMap::new(),
        }
    }

    /// Check and increment per-IP slot, keying on addr.ip() (correct).
    pub fn check_slot(&mut self, peer_addr: SocketAddr) -> bool {
        let ip = peer_addr.ip(); // extract stable identity
        let count = self.per_ip_count.get(&ip).copied().unwrap_or(0);
        if count >= MAX_INBOUND_CONCURRENCY_PER_IP {
            return false;
        }
        *self.per_ip_count.entry(ip).or_insert(0) += 1;
        true
    }
}
