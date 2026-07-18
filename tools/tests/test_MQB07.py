#!/usr/bin/env python3
"""Tests for ``tools/total-order-comparator-screen.py`` (MQ-B07).

MQ-B07 is a GENERAL enforcement-completeness screen, not a bug shape: for every
ordering-dependent comparator SINK (sort_by / sort_unstable_by / binary_search_by
/ min_by / max_by / a hand-written Ord|PartialOrd cmp body that BTreeMap|
BinaryHeap delegate to) it asks "is the delegated comparison a PROVEN total
order?" and emits an advisory (verdict=needs-fuzz) row ONLY when a partial order
is laundered into the sink (partial_cmp().unwrap()/.expect()/.unwrap_or()).

Coverage
--------
1.  test_planted_positive_fires             - sort_by with partial_cmp().unwrap() fires.
2.  test_cmp_negative_silent                - sort_by with `.cmp` (total order) stays silent.
3.  test_total_cmp_negative_silent          - partial_cmp swapped for f64::total_cmp stays silent.
4.  test_ordered_float_wrapper_silent       - an OrderedFloat/NotNan-wrapped comparator stays silent.
5.  test_sound_partialord_impl_silent       - `fn partial_cmp { Some(self.cmp(other)) }` stays silent.
6.  test_unsound_custom_ord_fires           - a custom `fn cmp` doing partial_cmp().unwrap() fires.
7.  test_sink_family_fires                  - min_by / max_by / binary_search_by all fire.
8.  test_test_code_excluded                 - patterns in `#[cfg(test)] mod` are ignored.
9.  test_advisory_first_default_exit_zero   - default run NEVER fail-closes (exit 0 with rows).
10. test_strict_opt_in_exit_one             - `--strict` exits 1 when a row is present.
11. test_row_schema_advisory_fields         - row carries verdict=needs-fuzz, auto_credit=False, advisory.
12. test_sidecar_emitted                    - <ws>/.auditooor/total_order_comparator_hypotheses.jsonl emitted.
13. test_non_vacuous_neutralize_sink        - neutralizing the sink predicate silences the positive.
14. test_non_vacuous_neutralize_soundness   - neutralizing the soundness predicate silences the positive.
15. test_real_fleet_mutation_verify         - NEAR views.rs `.cmp` sort_by silent; partial_cmp().unwrap() mutant fires.
16. test_real_fleet_known_positive          - NEAR blocks_delay_tracker partial_cmp().unwrap() sort_by is flagged.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "total-order-comparator-screen.py"
NEAR_VIEWS = Path(
    os.path.expanduser("~/audits/near/src/core/primitives/src/views.rs")
)
NEAR_BLOCKS_DELAY = Path(
    os.path.expanduser("~/audits/near/src/chain/chain/src/blocks_delay_tracker.rs")
)


def _load_module():
    """Load the hyphenated tool module in-process for predicate-level tests."""
    spec = importlib.util.spec_from_file_location("mqb07_mod", SCANNER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mqb07_mod"] = mod  # register BEFORE exec (py3.14 dataclass resolution)
    spec.loader.exec_module(mod)
    return mod


def _run_cli(workspace: Path, extra: list[str] | None = None) -> tuple[dict, int]:
    cmd = [sys.executable, str(SCANNER), "--workspace", str(workspace), "--print-json"]
    if extra:
        cmd.extend(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stdout + proc.stderr
    return json.loads(proc.stdout), proc.returncode


def _write(ws: Path, body: str, relpath: str = "src/order.rs") -> Path:
    p = ws / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


# Planted POSITIVE: a sort_by that launders a partial order (float NaN) into an
# ordering-dependent sink via unwrap. This is the general shape MQ-B07 fires on.
POSITIVE_BODY = """
    pub fn rank_scores(scores: &mut Vec<(u64, f64)>) {
        scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    }
"""

# Guarded NEGATIVE: a total-order `.cmp` comparator - silent.
CMP_BODY = """
    pub fn rank_ids(items: &mut Vec<Item>) {
        items.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.name.cmp(&b.name)));
    }
"""


class TestMQB07(unittest.TestCase):
    def test_planted_positive_fires(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_BODY)
            payload, _ = _run_cli(ws)
            self.assertGreaterEqual(payload["row_count"], 1)
            self.assertTrue(any(r["sink_kind"] == "sort_by" for r in payload["rows"]))
            self.assertTrue(
                any("partial_cmp" in r["unsound_signal"] for r in payload["rows"])
            )

    def test_cmp_negative_silent(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, CMP_BODY)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_total_cmp_negative_silent(self):
        body = """
        pub fn rank_scores(scores: &mut Vec<(u64, f64)>) {
            scores.sort_by(|a, b| a.1.total_cmp(&b.1));
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_ordered_float_wrapper_silent(self):
        # A float wrapped into a proven total order (OrderedFloat) - even with a
        # partial_cmp call the wrapper makes it sound, so it stays silent.
        body = """
        pub fn rank_scores(scores: &mut Vec<(u64, f64)>) {
            scores.sort_by(|a, b| OrderedFloat(a.1).partial_cmp(&OrderedFloat(b.1)).unwrap());
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_sound_partialord_impl_silent(self):
        # The canonical sound PartialOrd form delegating to Ord::cmp - no unwrap,
        # returns Option - must NOT fire.
        body = """
        impl PartialOrd for Host {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for Host {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.num.cmp(&other.num).then_with(|| self.id.cmp(&other.id))
            }
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_unsound_custom_ord_fires(self):
        # A hand-written Ord whose body launders a partial order that BTreeMap /
        # BinaryHeap would delegate to - must fire.
        body = """
        impl Ord for Weight {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.value.partial_cmp(&other.value).unwrap()
            }
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertGreaterEqual(payload["row_count"], 1)
            self.assertTrue(any(r["sink_kind"] == "impl_cmp" for r in payload["rows"]))

    def test_sink_family_fires(self):
        body = """
        pub fn pick(scores: &Vec<f64>, xs: &Vec<f64>, x: f64) {
            let _lo = scores.iter().min_by(|a, b| a.partial_cmp(b).unwrap());
            let _hi = scores.iter().max_by(|a, b| a.partial_cmp(b).unwrap());
            let _idx = xs.binary_search_by(|p| p.partial_cmp(&x).unwrap());
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            kinds = {r["sink_kind"] for r in payload["rows"]}
            self.assertIn("min_by", kinds)
            self.assertIn("max_by", kinds)
            self.assertIn("binary_search_by", kinds)

    def test_test_code_excluded(self):
        body = POSITIVE_BODY + """
        #[cfg(test)]
        mod tests {
            pub fn rank_evil(scores: &mut Vec<(u64, f64)>) {
                scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
            }
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertTrue(all("evil" not in r["function"] for r in payload["rows"]))

    def test_advisory_first_default_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_BODY)
            _payload, rc = _run_cli(ws)  # no --strict
            self.assertEqual(rc, 0)  # advisory-first: never fail-closes by default

    def test_strict_opt_in_exit_one(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_BODY)
            _payload, rc = _run_cli(ws, ["--strict"])
            self.assertEqual(rc, 1)

    def test_row_schema_advisory_fields(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_BODY)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["verdict_all"], "needs-fuzz")
            self.assertTrue(payload["advisory_first"])
            row = payload["rows"][0]
            for field in (
                "file", "line", "sink_kind", "function", "comparator",
                "unsound_signal", "invariant", "capability", "verdict",
                "auto_credit", "advisory",
            ):
                self.assertIn(field, row)
            self.assertEqual(row["verdict"], "needs-fuzz")
            self.assertFalse(row["auto_credit"])
            self.assertTrue(row["advisory"])
            self.assertEqual(row["capability"], "MQ-B07")

    def test_sidecar_emitted(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_BODY)
            # Default (non --print-json) run writes the sidecar under .auditooor.
            cmd = [sys.executable, str(SCANNER), "--workspace", str(ws)]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            sidecar = ws / ".auditooor" / "total_order_comparator_hypotheses.jsonl"
            self.assertTrue(sidecar.is_file(), "sidecar not emitted")
            lines = [l for l in sidecar.read_text().splitlines() if l.strip()]
            self.assertGreaterEqual(len(lines), 1)
            rec = json.loads(lines[0])
            for field in ("file", "line", "function", "capability", "verdict"):
                self.assertIn(field, rec)
            self.assertEqual(rec["verdict"], "needs-fuzz")
            self.assertFalse(rec["auto_credit"])
            self.assertEqual(rec["capability"], "MQ-B07")

    # -- Non-vacuity: neutralizing either half of the core predicate must make
    #    the planted positive disappear. -----------------------------------

    def test_non_vacuous_neutralize_sink(self):
        mod = _load_module()
        rel = "src/order.rs"
        text = textwrap.dedent(POSITIVE_BODY)
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # baseline fires
        orig = mod.classify_ordering_sink
        try:
            # Neutralize predicate half 1: nothing is an ordering sink.
            mod.classify_ordering_sink = lambda *a, **k: None
            self.assertEqual(mod.scan_text(text, rel), [])  # positive silenced
        finally:
            mod.classify_ordering_sink = orig
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # restored

    def test_non_vacuous_neutralize_soundness(self):
        mod = _load_module()
        rel = "src/order.rs"
        text = textwrap.dedent(POSITIVE_BODY)
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # baseline fires
        orig = mod.is_total_order_sound
        try:
            # Neutralize predicate half 2: pretend every comparator is a proven
            # total order.
            mod.is_total_order_sound = lambda *a, **k: True
            self.assertEqual(mod.scan_text(text, rel), [])  # positive silenced
        finally:
            mod.is_total_order_sound = orig
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # restored

    # -- Real-fleet mutation verify (read-only; never mutate the ws file). ---

    @unittest.skipUnless(NEAR_VIEWS.is_file(), "NEAR fleet snapshot absent")
    def test_real_fleet_mutation_verify(self):
        mod = _load_module()
        original = NEAR_VIEWS.read_text(encoding="utf-8")

        # Guarded original: SILENT. The `costs.sort_by(...)` comparator uses a
        # total-order `.cmp` chain, so no partial order is laundered.
        rows_guarded = mod.scan_text(original, "views.rs")
        self.assertEqual(
            rows_guarded, [], f"expected silent on total-order source, got {rows_guarded}"
        )

        # Mutant (temp copy, comparator weakened): replace the total-order `.cmp`
        # with a laundered partial order. Must FIRE. Never mutate the ws file.
        mutant = original.replace(
            "lhs.cost_category.cmp(&rhs.cost_category)",
            "lhs.cost_category.partial_cmp(&rhs.cost_category).unwrap()",
        )
        self.assertNotEqual(mutant, original, "mutation string failed to apply")
        rows_mutant = mod.scan_text(mutant, "views.rs")
        self.assertGreaterEqual(len(rows_mutant), 1, "expected fire when total order weakened")
        self.assertTrue(any(r.sink_kind == "sort_by" for r in rows_mutant))
        self.assertTrue(any("partial_cmp" in r.unsound_signal for r in rows_mutant))

    @unittest.skipUnless(NEAR_BLOCKS_DELAY.is_file(), "NEAR fleet snapshot absent")
    def test_real_fleet_known_positive(self):
        # blocks_delay_tracker.rs has a real `sort_by(|..| ..partial_cmp(..).unwrap())`
        # (integer tuple today, but the fragile laundered shape MQ-B07 flags
        # advisory / needs-fuzz). It must be enumerated.
        mod = _load_module()
        text = NEAR_BLOCKS_DELAY.read_text(encoding="utf-8")
        rows = mod.scan_text(text, "blocks_delay_tracker.rs")
        self.assertTrue(
            any(
                r.sink_kind == "sort_by" and "partial_cmp" in r.unsound_signal
                for r in rows
            ),
            f"expected the partial_cmp().unwrap() sort_by to be flagged, got {rows}",
        )


if __name__ == "__main__":
    unittest.main()
