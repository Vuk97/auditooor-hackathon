// clean.rs - should NOT fire: safe variants using saturating_sub or checked_sub

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Height(pub u32);

pub struct CheckpointVerifier {
    queued: BTreeMap<Height, String>,
}

impl CheckpointVerifier {
    // Safe variant 1: uses saturating_sub - should NOT fire
    fn target_checkpoint_height_saturating(&self, start_height: Height) -> Option<Height> {
        let mut pending_height = start_height;
        for (&height, _) in self.queued.range((Excluded(pending_height), Unbounded)) {
            if height == Height(pending_height.0 + 1) {
                pending_height = height;
            } else {
                let gap = height.0.saturating_sub(pending_height.0);
                log_gap(gap);
                break;
            }
        }
        Some(pending_height)
    }

    // Safe variant 2: uses checked_sub - should NOT fire
    fn target_checkpoint_height_checked(&self, start_height: Height) -> Option<Height> {
        let mut pending_height = start_height;
        for (&height, _) in self.queued.range((Excluded(pending_height), Unbounded)) {
            if height == Height(pending_height.0 + 1) {
                pending_height = height;
            } else {
                let gap = height.0.checked_sub(pending_height.0).unwrap_or(0);
                log_gap(gap);
                break;
            }
        }
        Some(pending_height)
    }

    // Safe variant 3: bare sub but no .range() / no continuity guard - should NOT fire
    fn compute_depth(&self, tip: Height, h: Height) -> u32 {
        // No BTreeMap range walk; just a bare depth calculation elsewhere
        tip.0 - h.0
    }
}

fn log_gap(_gap: u32) {}
