#!/usr/bin/env python3
"""RU1: swival_unsafe_impl_send_sync_unjustified detector tests.

Non-vacuous: each case pins the *justification* predicate. If the predicate is
relaxed (drop the raw-cell gate, drop the # Safety/Mutex suppressor, or the
per-impl doc-attribution) at least one assertion below breaks.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "base-rust-swival-shape-scan.py"
FIX = Path(__file__).resolve().parent / "fixtures" / "RU1"


def _load():
    spec = importlib.util.spec_from_file_location("base_rust_swival_shape_scan", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["base_rust_swival_shape_scan"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _ws(rel: str, body: str) -> Path:
    tmp = Path(tempfile.mkdtemp())
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return tmp


def _scan(ws: Path):
    return MOD.scan_unsafe_impl_send_sync(ws, ["src"])


class RU1Tests(unittest.TestCase):
    def test_flags_unjustified_unsafe_sync(self) -> None:
        ws = _ws(
            "src/vm.rs",
            """
            pub struct G {
                cell: std::cell::UnsafeCell<u64>,
            }
            unsafe impl Sync for G {}
            """,
        )
        hits = _scan(ws)
        self.assertEqual(len(hits), 1, hits)
        h = hits[0]
        self.assertEqual(h["detector"], "swival_unsafe_impl_send_sync_unjustified")
        self.assertEqual(h["verdict"], "needs-fuzz")
        self.assertTrue(h["advisory"])
        self.assertEqual(h["impl_trait"], "Sync")
        self.assertEqual(h["submission_posture"], "NOT_SUBMIT_READY")

    def test_safety_doc_suppresses(self) -> None:
        ws = _ws(
            "src/vm.rs",
            """
            pub struct G {
                cell: std::cell::UnsafeCell<u64>,
            }
            /// # Safety
            /// no thread-specific logic.
            unsafe impl Sync for G {}
            """,
        )
        self.assertEqual(_scan(ws), [])

    def test_mutex_in_struct_suppresses(self) -> None:
        ws = _ws(
            "src/vm.rs",
            """
            pub struct G {
                cell: std::cell::UnsafeCell<u64>,
                lock: parking_lot::Mutex<()>,
            }
            unsafe impl Sync for G {}
            """,
        )
        self.assertEqual(_scan(ws), [])

    def test_no_raw_cell_not_flagged(self) -> None:
        ws = _ws(
            "src/vm.rs",
            """
            pub struct G {
                x: u64,
            }
            unsafe impl Sync for G {}
            """,
        )
        self.assertEqual(_scan(ws), [])

    def test_neighbour_doc_does_not_falsely_justify(self) -> None:
        # Send has a # Safety doc; Sync does not. Only Sync must fire -
        # proves per-impl doc attribution, not a shared window.
        ws = _ws(
            "src/vm.rs",
            """
            pub struct G {
                p: *mut u64,
            }
            /// # Safety
            /// send is fine.
            unsafe impl Send for G {}
            unsafe impl Sync for G {}
            """,
        )
        hits = _scan(ws)
        self.assertEqual([h["impl_trait"] for h in hits], ["Sync"], hits)

    def test_benign_fixture_clean_mutant_fires(self) -> None:
        # global_benign.rs = Mutex + # Safety -> clean. global_mutant.rs =
        # stripped -> Sync fires. Mutation-kill on-disk fixtures.
        benign = _ws("src/global.rs", FIX.joinpath("global_benign.rs").read_text())
        mutant = _ws("src/global.rs", FIX.joinpath("global_mutant.rs").read_text())
        self.assertEqual(_scan(benign), [])
        mut = _scan(mutant)
        self.assertEqual([h["impl_trait"] for h in mut], ["Sync"], mut)

    def test_dedup_covered_by_field_present(self) -> None:
        ws = _ws(
            "src/vm.rs",
            """
            pub struct G {
                cell: std::cell::UnsafeCell<u64>,
            }
            unsafe impl Sync for G {}
            """,
        )
        h = _scan(ws)[0]
        # Distinct surface from the presence-only base detector: no overlap.
        self.assertIn("covered_by", h)
        self.assertEqual(h["covered_by"], "")

    def test_axis_off_by_default_cli(self) -> None:
        ws = _ws(
            "src/vm.rs",
            """
            pub struct G {
                cell: std::cell::UnsafeCell<u64>,
            }
            unsafe impl Sync for G {}
            """,
        )
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(ws), "--scan-root", "src"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        hyp = ws / "critical_hunt/swival_shape_scan/unsafe_impl_send_sync_hypotheses.jsonl"
        self.assertFalse(hyp.exists(), "axis must be OFF by default")

    def test_axis_on_writes_jsonl(self) -> None:
        ws = _ws(
            "src/vm.rs",
            """
            pub struct G {
                cell: std::cell::UnsafeCell<u64>,
            }
            unsafe impl Sync for G {}
            """,
        )
        out = ws / "hyps.jsonl"
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--scan-root",
                "src",
                "--unsafe-impl-axis",
                "--out-unsafe-impl-jsonl",
                str(out),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(out.is_file())
        rec = json.loads(out.read_text().splitlines()[0])
        self.assertEqual(rec["verdict"], "needs-fuzz")


if __name__ == "__main__":
    unittest.main()
