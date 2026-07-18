"""RU3 - advisory rust-OOB axis (copy_from_slice / untrusted-offset slice-range).

Non-vacuous: each predicate is load-bearing. Mutating it flips a case:
  * guard-dominance      -> guarded copy (min-clamp) must NOT fire; strip it -> fire
  * separate-buffer req  -> a NEW slice_range fires only on a buffer != ingress
  * alloc-exclusion (A1) -> a copy/slice on a with_capacity/vec! line is excluded
  * env-gating           -> the axis is OFF unless AUDITOOR_RUST_OOB_AXIS is set
  * NO-AUTO-CREDIT        -> every hit carries verdict=needs-fuzz

The axis lives in its own stream (summary["rust_oob_axis"]); the default RU1
pattern + totals are unchanged when the axis is off.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER_PATH = HERE.parent / "rust-detector-runner.py"
FIX = HERE / "fixtures" / "RU3"
ENV = "AUDITOOR_RUST_OOB_AXIS"


def _load_runner():
    spec = importlib.util.spec_from_file_location("rust_detector_runner_ru3",
                                                  RUNNER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rust_detector_runner_ru3"] = mod
    spec.loader.exec_module(mod)
    return mod


# copy_from_slice: whole untrusted `data` -> `buf`, no in-fn length guard.
UNGUARDED_COPY = """
pub fn read_exact(buf: &mut [u8], data: Vec<u8>) {
    buf[..].copy_from_slice(&data[..]);
}
"""

# copy_from_slice guarded by a dominating .min(buf.len()) clamp -> no fire.
GUARDED_COPY = """
pub fn read(buf: &mut [u8], data: Vec<u8>) -> usize {
    let len = data.len().min(buf.len());
    buf[..len].copy_from_slice(&data[..len]);
    len
}
"""

# slice_range on a SEPARATE (non-ingress) buffer, bound refs untrusted len.
SEPARATE_RANGE = """
pub fn lookup(data: &[u8]) -> u8 {
    let scratch = fetch_table();
    scratch[..data.len()][0]
}
"""

# copy_from_slice on a vec!/with_capacity ALLOC line -> A1 dedup exclusion.
ALLOC_LINE = """
pub fn fill(buf: &mut [u8], data: Vec<u8>) {
    buf.copy_from_slice(&vec![0u8; data.len()]);
}
"""

# bracket-less copy_from_slice: net-new (no overlapping RU1 slice_index).
NET_NEW_COPY = """
pub fn exact(buf: &mut [u8], value: Vec<u8>) {
    buf.copy_from_slice(value.as_slice());
}
"""


def _oob(mod, src: str, enabled: bool):
    prev = os.environ.get(ENV)
    if enabled:
        os.environ[ENV] = "1"
    else:
        os.environ.pop(ENV, None)
    try:
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "f.rs").write_text(src, encoding="utf-8")
            summary = mod.scan_workspace(Path(ws))
    finally:
        if prev is None:
            os.environ.pop(ENV, None)
        else:
            os.environ[ENV] = prev
    return summary


def _hyps(summary):
    return (summary.get("rust_oob_axis") or {}).get("hypotheses", [])


def _kinds(summary):
    return sorted(h["extra"]["sink_kind"] for h in _hyps(summary))


class RU3OobAxisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    def test_env_off_no_axis(self):
        s = _oob(self.mod, UNGUARDED_COPY, enabled=False)
        self.assertNotIn("rust_oob_axis", s,
                         "axis must be OFF by default (advisory-first)")

    def test_unguarded_copy_from_slice_fires(self):
        s = _oob(self.mod, UNGUARDED_COPY, enabled=True)
        self.assertIn("copy_from_slice", _kinds(s))

    def test_guarded_copy_no_fire(self):
        # Load-bearing: the .min(buf.len()) clamp dominates the copy sink.
        s = _oob(self.mod, GUARDED_COPY, enabled=True)
        self.assertNotIn("copy_from_slice", _kinds(s),
                         "min-clamp dominates the copy; must not fire")

    def test_separate_buffer_slice_range_fires(self):
        s = _oob(self.mod, SEPARATE_RANGE, enabled=True)
        self.assertIn("slice_range", _kinds(s),
                      "separate buffer indexed by untrusted len must fire")

    def test_alloc_line_excluded(self):
        # Load-bearing (A1): a copy on a vec!/with_capacity line is excluded
        # (already covered by RU2 + the 2 alloc scanners).
        s = _oob(self.mod, ALLOC_LINE, enabled=True)
        self.assertEqual(_hyps(s), [],
                         "alloc-line sink must be excluded (dedup boundary)")

    def test_net_new_copy_covered_by_none(self):
        # bracket-less receiver -> no overlapping RU1 slice_index -> net-new.
        s = _oob(self.mod, NET_NEW_COPY, enabled=True)
        hyps = _hyps(s)
        self.assertGreaterEqual(len(hyps), 1)
        self.assertIsNone(hyps[0]["extra"]["covered_by"])
        self.assertGreaterEqual(s["rust_oob_axis"]["net_new_count"], 1)

    def test_covered_by_tag_on_overlap(self):
        # buf[..].copy_from_slice overlaps the RU1 slice_index hit on buf[..].
        s = _oob(self.mod, UNGUARDED_COPY, enabled=True)
        cp = [h for h in _hyps(s) if h["extra"]["sink_kind"] == "copy_from_slice"]
        self.assertTrue(cp)
        self.assertEqual(cp[0]["extra"]["covered_by"],
                         "rust.panic.untrusted_ingress_unguarded_panic#slice_index")

    def test_needs_fuzz_no_auto_credit(self):
        s = _oob(self.mod, UNGUARDED_COPY, enabled=True)
        ax = s["rust_oob_axis"]
        self.assertEqual(ax["verdict"], "needs-fuzz")
        self.assertFalse(ax["auto_credit"])
        for h in _hyps(s):
            self.assertEqual(h["extra"]["verdict"], "needs-fuzz")
            self.assertEqual(h["extra"]["axis"], "rust-OOB")

    def test_default_ru1_pattern_unchanged_when_off(self):
        # With axis off, the RU1 pattern still fires on the raw buf[..] index.
        s = _oob(self.mod, UNGUARDED_COPY, enabled=False)
        pid = "rust.panic.untrusted_ingress_unguarded_panic"
        self.assertGreaterEqual(s["patterns"][pid]["hit_count"], 1)

    def test_channel_fixture_matches_native_shape(self):
        prev = os.environ.get(ENV)
        os.environ[ENV] = "1"
        try:
            with tempfile.TemporaryDirectory() as ws:
                (Path(ws) / "c.rs").write_text(
                    (FIX / "channel_like.rs").read_text(), encoding="utf-8")
                s = self.mod.scan_workspace(Path(ws))
        finally:
            if prev is None:
                os.environ.pop(ENV, None)
            else:
                os.environ[ENV] = prev
        # read (guarded) -> no fire; read_exact (unguarded) -> 1 copy sink.
        cp = [h for h in _hyps(s) if h["extra"]["sink_kind"] == "copy_from_slice"]
        self.assertEqual(len(cp), 1, f"expected 1 copy sink, got {cp}")
        self.assertEqual(cp[0]["extra"]["function"], "read_exact")

    def test_jsonl_written(self):
        prev = os.environ.get(ENV)
        os.environ[ENV] = "1"
        try:
            with tempfile.TemporaryDirectory() as ws:
                (Path(ws) / "f.rs").write_text(NET_NEW_COPY, encoding="utf-8")
                summary = self.mod.scan_workspace(Path(ws))
                self.mod._write_outputs(Path(ws), summary)
                jl = Path(ws) / ".auditooor" / "rust_oob_hypotheses.jsonl"
                self.assertTrue(jl.exists())
                rows = [json.loads(x) for x in jl.read_text().splitlines() if x]
                self.assertTrue(rows)
                self.assertEqual(rows[0]["verdict"], "needs-fuzz")
                self.assertEqual(rows[0]["sink_kind"], "copy_from_slice")
        finally:
            if prev is None:
                os.environ.pop(ENV, None)
            else:
                os.environ[ENV] = prev


if __name__ == "__main__":
    unittest.main()
