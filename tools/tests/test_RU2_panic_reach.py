#!/usr/bin/env python3
"""RU2 / R11 - untrusted-ingress -> reachable panic-primitive advisory axis.

Non-vacuous: each POSITIVE asserts a specific sink hit, each NEGATIVE asserts
the ABSENCE, and the mutation-witness pair (unclamped alloc FIRES vs the same
body with a `.min(MAX_LEN)` clamp SILENT) proves the guard-dominance predicate
has teeth (an equivalent mutant would break a case). Covers all four required
axes from the R11 brief:

  (i)   decode entrypoint reads a length then `vec![0; n]` (no clamp) -> FIRES
        sink_kind=unbounded_alloc (net-new: RU1 has no alloc primitive).
  (ii)  the SAME body clamped by `let n = n.min(MAX_LEN);` -> 0 hits (the
        guard-dominance mutation witness / non-vacuity anchor).
  (iii) a plain `bytes[i]` that RU1 already emits -> tagged covered_by=RU1 and
        excluded from net_new (the A1 dedup boundary).
  (iv)  the axis is silent unless AUDITOOR_RUST_PANIC_REACH_AXIS is set.

Plus the brief's top-level contract: a pub fn that indexes/unwraps/allocates
from an attacker value with no guard FIRES; the same guarded by a bounds-check
/ `.get()` / clamp / checked-arith is SILENT.
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


def _load():
    spec = importlib.util.spec_from_file_location("rust_detector_runner_ru2", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rust_detector_runner_ru2"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()

_SIBLING = "rust.panic.untrusted_ingress_unguarded_panic"


def _write(ws: Path, rel: str, body: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def _axis(ws: Path) -> dict:
    os.environ["AUDITOOR_RUST_PANIC_REACH_AXIS"] = "1"
    summary = MOD.scan_workspace(ws)
    return summary.get("rust_panic_reach_axis", {})


def _hits(ws: Path):
    return _axis(ws).get("hypotheses", [])


class RU2Tests(unittest.TestCase):
    # ------------------------------------------------------------------
    # (i) POSITIVE - decode entrypoint decodes a length -> unbounded alloc.
    # ------------------------------------------------------------------
    def test_decode_entrypoint_unbounded_alloc_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/a.rs", """
                pub fn decode(data: &[u8]) -> Vec<u8> {
                    let len_bytes = data;
                    let n = read_len(len_bytes) as usize;
                    let out = vec![0u8; n];
                    out
                }
                """)
            hits = _hits(ws)
            self.assertEqual(len(hits), 1)
            ex = hits[0]["extra"]
            self.assertEqual(ex["sink_kind"], "unbounded_alloc")
            self.assertEqual(ex["ingress_param"], "data")
            self.assertEqual(ex["ingress_seam"], "decoded_value")
            self.assertGreaterEqual(ex["taint_hops"], 1)
            self.assertIsNone(ex["covered_by"])

    # ------------------------------------------------------------------
    # (ii) NEGATIVE / mutation-witness - a `.min(MAX_LEN)` clamp suppresses it.
    # ------------------------------------------------------------------
    def test_clamp_suppresses_unbounded_alloc(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/b.rs", """
                pub fn decode(data: &[u8]) -> Vec<u8> {
                    const MAX_LEN: usize = 1024;
                    let len_bytes = data;
                    let n = read_len(len_bytes) as usize;
                    let n = n.min(MAX_LEN);
                    let out = vec![0u8; n];
                    out
                }
                """)
            self.assertEqual(len(_hits(ws)), 0)

    # ------------------------------------------------------------------
    # (iii) DEDUP - a plain `bytes[i]` RU1 already emits is covered_by=RU1
    # and excluded from net_new.
    # ------------------------------------------------------------------
    def test_ru1_overlap_deduped(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/c.rs", """
                pub fn parse(bytes: &[u8]) -> u8 {
                    bytes[0]
                }
                """)
            axis = _axis(ws)
            hits = axis.get("hypotheses", [])
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["extra"]["sink_kind"], "index_slice")
            self.assertEqual(hits[0]["extra"]["covered_by"], _SIBLING)
            self.assertEqual(axis["net_new_count"], 0)
            self.assertEqual(axis["hypothesis_count"], 1)

    # ------------------------------------------------------------------
    # (iv) env-gate - silent unless the axis env is set.
    # ------------------------------------------------------------------
    def test_axis_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/a.rs", """
                pub fn decode(data: &[u8]) -> Vec<u8> {
                    let n = read_len(data) as usize;
                    vec![0u8; n]
                }
                """)
            os.environ.pop("AUDITOOR_RUST_PANIC_REACH_AXIS", None)
            summary = MOD.scan_workspace(ws)
            self.assertNotIn("rust_panic_reach_axis", summary)

    def test_needs_fuzz_no_auto_credit(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/a.rs", """
                pub fn decode(data: &[u8]) -> Vec<u8> {
                    let n = read_len(data) as usize;
                    vec![0u8; n]
                }
                """)
            axis = _axis(ws)
            self.assertEqual(axis["verdict"], "needs-fuzz")
            self.assertFalse(axis["auto_credit"])
            self.assertEqual(axis["sibling_detector"], _SIBLING)
            ex = axis["hypotheses"][0]["extra"]
            self.assertEqual(ex["verdict"], "needs-fuzz")
            self.assertEqual(
                ex["impact_contract"]["status"], "advisory_needs_fuzz"
            )

    # ------------------------------------------------------------------
    # NET-NEW over RU1: a derived-scalar index (RU1 keys only same-var names).
    # ------------------------------------------------------------------
    def test_derived_scalar_index_net_new_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/d.rs", """
                pub fn decode(data: &[u8]) -> u8 {
                    let idx = compute(data);
                    let table = [0u8; 16];
                    table[idx]
                }
                """)
            hits = _hits(ws)
            self.assertEqual(len(hits), 1)
            ex = hits[0]["extra"]
            self.assertEqual(ex["sink_kind"], "index_slice")
            self.assertEqual(ex["ingress_seam"], "decoded_value")
            self.assertIsNone(ex["covered_by"])

    def test_bounds_check_suppresses_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/e.rs", """
                pub fn decode(data: &[u8]) -> u8 {
                    let idx = compute(data);
                    if idx >= 16 { return 0; }
                    let table = [0u8; 16];
                    table[idx]
                }
                """)
            self.assertEqual(len(_hits(ws)), 0)

    def test_get_method_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/f.rs", """
                pub fn decode(data: &[u8]) -> Option<u8> {
                    data.get(3).copied()
                }
                """)
            self.assertEqual(len(_hits(ws)), 0)

    # ------------------------------------------------------------------
    # unwrap/expect primitive on a DERIVED local.
    # ------------------------------------------------------------------
    def test_unwrap_on_derived_local_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/g.rs", """
                pub fn decode(data: &[u8]) -> u8 {
                    let opt = parse_opt(data);
                    opt.unwrap()
                }
                """)
            hits = _hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["extra"]["sink_kind"], "unwrap_expect")

    # ------------------------------------------------------------------
    # unchecked arithmetic underflow vs saturating_sub (mutation witness).
    # ------------------------------------------------------------------
    def test_unchecked_underflow_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/h.rs", """
                pub fn prune(data: &[u8]) -> usize {
                    let count = decode_count(data);
                    count - 1
                }
                """)
            hits = _hits(ws)
            self.assertEqual(len(hits), 1)
            ex = hits[0]["extra"]
            self.assertEqual(ex["sink_kind"], "unchecked_arith")
            # ingress param seam (no decode-entrypoint name; plain byte param).
            self.assertEqual(ex["ingress_param"], "data")

    def test_saturating_sub_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/i.rs", """
                pub fn prune(data: &[u8]) -> usize {
                    let count = decode_count(data);
                    count.saturating_sub(1)
                }
                """)
            self.assertEqual(len(_hits(ws)), 0)

    # ------------------------------------------------------------------
    # A non-ingress fn with no attacker seam stays silent (no over-fire).
    # ------------------------------------------------------------------
    def test_no_ingress_seam_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/j.rs", """
                pub fn helper(cfg: &Config) -> usize {
                    let n = cfg.fixed_len;
                    let out = vec![0u8; n];
                    out.len()
                }
                """)
            self.assertEqual(len(_hits(ws)), 0)

    # ------------------------------------------------------------------
    # test-context FP guard - a #[test] fn's fixture param is not ingress.
    # ------------------------------------------------------------------
    def test_test_attr_fn_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/t.rs", """
                #[test]
                fn decode(data: &[u8]) -> usize {
                    let n = read_len(data) as usize;
                    let out = vec![0u8; n];
                    out.len()
                }
                """)
            self.assertEqual(len(_hits(ws)), 0)

    # ------------------------------------------------------------------
    # DEFECT-2 tether - an UNRELATED early `return Err` does not suppress a
    # later genuine tainted-index sink (shared _guard_dominates fix).
    # ------------------------------------------------------------------
    def test_unrelated_early_err_still_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/k.rs", """
                pub fn decode(flag: bool, data: &[u8]) -> Result<u8, ()> {
                    if !flag {
                        return Err(());
                    }
                    let idx = compute(data);
                    let table = [0u8; 16];
                    Ok(table[idx])
                }
                """)
            hits = _hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["extra"]["sink_kind"], "index_slice")

    def test_jsonl_emitted_with_brief_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/a.rs", """
                pub fn decode(data: &[u8]) -> Vec<u8> {
                    let n = read_len(data) as usize;
                    vec![0u8; n]
                }
                """)
            os.environ["AUDITOOR_RUST_PANIC_REACH_AXIS"] = "1"
            summary = MOD.scan_workspace(ws)
            MOD._write_outputs(ws, summary)
            jsonl = ws / ".auditooor" / "rust_panic_reach_hypotheses.jsonl"
            self.assertTrue(jsonl.exists())
            import json
            rows = [json.loads(x) for x in jsonl.read_text().splitlines() if x]
            self.assertEqual(len(rows), 1)
            r = rows[0]
            for key in ("file", "line", "primitive", "ingress", "path",
                        "attack_class", "verdict"):
                self.assertIn(key, r)
            self.assertEqual(r["attack_class"], "untrusted-panic-dos")
            self.assertEqual(r["verdict"], "needs-fuzz")
            self.assertEqual(r["primitive"], "unbounded_alloc")


if __name__ == "__main__":
    unittest.main()
