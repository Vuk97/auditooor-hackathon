#!/usr/bin/env python3
"""RU6 - nondeterminism -> consensus-divergence advisory axis.

Non-vacuous: each positive asserts a specific hit, each negative asserts the
absence; mutating the predicate (dropping the ORDERED-SINK teeth or the
BTreeMap/sort guard) breaks a case. Also pins the mutation-verified base-azul
:192 negative control (idempotent cache-load must NOT fire; ordered Vec-push
mutant must fire).
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-detector-runner.py"
FIX = Path(__file__).resolve().parent / "fixtures" / "RU6"


def _load():
    spec = importlib.util.spec_from_file_location("rust_detector_runner_ru6", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rust_detector_runner_ru6"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _write(ws: Path, rel: str, body: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def _nondet_hits(ws: Path):
    os.environ["AUDITOOR_RUST_NONDET_AXIS"] = "1"
    summary = MOD.scan_workspace(ws)
    axis = summary.get("rust_nondet_axis", {})
    return axis.get("hypotheses", [])


class RU6Tests(unittest.TestCase):
    def test_map_iter_ordered_sink_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/execution/engine-tree/src/a.rs", """
                use std::collections::HashMap;
                fn build_root(accounts: &HashMap<Address, u64>) -> Vec<Address> {
                    let mut ordered = Vec::new();
                    for k in accounts.keys() {
                        ordered.push(*k);
                    }
                    ordered
                }
                """)
            hits = _nondet_hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["extra"]["source_kind"], "hashmap_iteration")

    def test_map_iter_idempotent_no_sink_silent(self):
        # Negative control shape (base-azul :192): iterate keys but only an
        # idempotent load, no ordered sink -> MUST NOT fire.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/execution/engine-tree/src/b.rs", """
                use std::collections::HashMap;
                fn warm(cache: &HashMap<Address, u64>, db: &mut Db) {
                    for k in cache.keys() {
                        db.load_cache_account(*k);
                    }
                }
                """)
            self.assertEqual(len(_nondet_hits(ws)), 0)

    def test_btreemap_guard_suppresses(self):
        # Same ordered-sink shape but a BTreeMap in-fn = deterministic guard.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/execution/engine-tree/src/c.rs", """
                use std::collections::BTreeMap;
                fn build_root(accounts: &BTreeMap<Address, u64>) -> Vec<Address> {
                    let mut ordered = Vec::new();
                    for k in accounts.keys() {
                        ordered.push(*k);
                    }
                    ordered
                }
                """)
            self.assertEqual(len(_nondet_hits(ws)), 0)

    def test_sort_guard_suppresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/execution/engine-tree/src/d.rs", """
                use std::collections::HashMap;
                fn build_root(accounts: &HashMap<Address, u64>) -> Vec<Address> {
                    let mut ordered: Vec<Address> = accounts.keys().cloned().collect();
                    ordered.sort();
                    ordered
                }
                """)
            self.assertEqual(len(_nondet_hits(ws)), 0)

    def test_float_arm_gated_to_consensus_path(self):
        # float arith -> state_root write: fires in an execution module...
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/execution/trie/src/f.rs", """
                fn compute(x: u64) {
                    let ratio: f64 = (x as f64) * 2.0;
                    self.state_root = keccak(ratio as u64);
                }
                """)
            hits = _nondet_hits(ws)
            self.assertEqual([h["extra"]["source_kind"] for h in hits], ["float_arith"])

    def test_float_arm_silent_outside_consensus_path(self):
        # ...but NOT in an rpc/metrics module (same body, benign there).
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/rpc/src/f.rs", """
                fn compute(x: u64) {
                    let ratio: f64 = (x as f64) * 2.0;
                    self.state_root = keccak(ratio as u64);
                }
                """)
            self.assertEqual(len(_nondet_hits(ws)), 0)

    def test_time_arm_metrics_push_silent(self):
        # Instant::now pushed to a latency Vec (metrics) = benign, no state sink.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/execution/engine-tree/src/t.rs", """
                fn record(&mut self) {
                    let now = Instant::now();
                    self.latencies.push(now);
                }
                """)
            self.assertEqual(len(_nondet_hits(ws)), 0)

    def test_axis_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/execution/engine-tree/src/a.rs", """
                use std::collections::HashMap;
                fn build_root(m: &HashMap<Address, u64>) -> Vec<Address> {
                    let mut o = Vec::new();
                    for k in m.keys() { o.push(*k); }
                    o
                }
                """)
            os.environ.pop("AUDITOOR_RUST_NONDET_AXIS", None)
            summary = MOD.scan_workspace(ws)
            self.assertNotIn("rust_nondet_axis", summary)

    def test_committed_fixtures(self):
        # Fixture pair pinned on disk (clean=0, mutant=1) - the mutation-kill.
        clean = _nondet_hits(FIX / "clean")
        mut = _nondet_hits(FIX / "mutant")
        self.assertEqual(len(clean), 0)
        self.assertEqual(len(mut), 1)


if __name__ == "__main__":
    unittest.main()
