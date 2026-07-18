// positive.rs - SHOULD fire: bare .0 - .0 subtraction on Height newtypes
// inside a BTreeMap range iteration where the only guard is logic-based.

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Height(pub u32);

pub struct CheckpointVerifier {
    queued: BTreeMap<Height, String>,
}

impl CheckpointVerifier {
    // Mirrors zebra-consensus/src/checkpoint.rs fn target_checkpoint_height
    // The loop invariant (height > pending_height) is maintained only by the
    // `if height == Height(pending_height.0 + 1)` branch, not by the type system.
    fn target_checkpoint_height(&self, start_height: Height) -> Option<Height> {
        let mut pending_height = start_height;
        for (&height, _) in self.queued.range((Excluded(pending_height), Unbounded)) {
            if height == Height(pending_height.0 + 1) {
                pending_height = height;
            } else {
                // VULN: bare u32 subtraction - panics in debug if invariant violated
                let gap = height.0 - pending_height.0;
                tracing_stub(gap);
                break;
            }
        }
        Some(pending_height)
    }
}

fn tracing_stub(_gap: u32) {}
