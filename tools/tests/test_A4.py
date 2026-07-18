#!/usr/bin/env python3
"""A4 namespace-uniqueness lane - non-vacuous regression.

Pins the uniqueness-sink class added to tools/dataflow-slice.py: it flags
keyed-store per-key uniqueness WRITES (map[k]= / .insert(k) / nonce_slot
.replace(true) / nullifier.push) reachable with NO dominating per-key guard.
Every emitted row is verdict="needs-fuzz" (NO-AUTO-CREDIT); advisory-first.

Mutation-verify anchor: near-intents used_nonces.rs:104
`require!(!nonce_slot.replace(true), ErrorCode::NonceAlreadyUsed)`. The CLEAN
(guarded) copy must NOT fire; the MUTANT (guard stripped) MUST fire.

Non-vacuity: mutating the guard predicate breaks a case.
  - guard OFF (never see the check-and-set) -> the CLEAN fixture fires (asserted
    NOT to, so a broken guard predicate fails the test).
  - FP-guard OFF -> the monotone-counter fixture fires (asserted suppressed).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "A4"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "dataflow_slice_a4", TOOLS / "dataflow-slice.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


A4 = _load_tool()


def _scan(fixture_name):
    """Scan one fixture; return (emitted-needs-fuzz rows, accounting)."""
    f = FX / fixture_name
    hyps, acc = A4.uniqueness_scan(str(FX), targets=[str(f)])
    emitted = [h for h in hyps if not h["covered_by"]]
    return emitted, acc, hyps


class TestUniquenessSink(unittest.TestCase):

    def test_clean_guarded_does_not_fire(self):
        emitted, acc, _ = _scan("used_nonces_clean.rs")
        self.assertEqual(acc["sinks_detected"], 1,
                         "the .replace(true) sink must be DETECTED")
        self.assertEqual(acc["guarded_suppressed"], 1,
                         "the check-and-set require! must be seen as the guard")
        self.assertEqual(emitted, [],
                         "a guarded per-key write must NOT be flagged")

    def test_mutant_unguarded_fires(self):
        emitted, acc, _ = _scan("used_nonces_mutant.rs")
        self.assertEqual(len(emitted), 1,
                         "stripping the guard must fire exactly one hypothesis")
        row = emitted[0]
        self.assertEqual(row["verdict"], "needs-fuzz")
        self.assertEqual(row["sink_kind"], "bitset-replace")
        self.assertEqual(row["collection"], "nonce_slot")
        self.assertEqual(row["fn"], "use_nonce")
        self.assertIsNone(row["covered_by"])
        self.assertEqual(row["attack_class"], "namespace-uniqueness-replay")

    def test_set_insert_guarded_and_unguarded(self):
        emitted, acc, _ = _scan("set_insert.rs")
        self.assertEqual(acc["sinks_detected"], 2)
        self.assertEqual(acc["guarded_suppressed"], 1,
                         "require!(set.insert(..)) is a check-and-set guard")
        self.assertEqual(len(emitted), 1,
                         "only the bare insert is unguarded")
        self.assertEqual(emitted[0]["sink_kind"], "set-insert")
        self.assertEqual(emitted[0]["fn"], "spend_unguarded")

    def test_monotone_counter_key_suppressed_fp(self):
        emitted, acc, _ = _scan("counter_fp.rs")
        self.assertEqual(acc["sinks_detected"], 1)
        self.assertEqual(acc["fp_suppressed"], 1,
                         "a monotone internal-counter key is structural uniqueness")
        self.assertEqual(emitted, [])

    def test_dedup_covered_by_named_detector(self):
        # A1 boundary: a hit whose file:line the signature-replay sidecar already
        # flags is marked covered_by and dropped from the needs-fuzz count. We do
        # NOT re-derive that signal - we READ it.
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="a4_dedup_"))
        try:
            (tmp / ".auditooor").mkdir(parents=True)
            src = (FX / "used_nonces_mutant.rs").read_text()
            (tmp / "used_nonces_mutant.rs").write_text(src)
            # emit a fake existing signature-replay hit at the SAME loc
            loc = "used_nonces_mutant.rs:9"
            (tmp / ".auditooor" / "signature_replay_hypotheses.jsonl").write_text(
                json.dumps({"file_line": loc, "verdict": "needs-fuzz"}) + "\n")
            hyps, acc = A4.uniqueness_scan(
                str(tmp), targets=[str(tmp / "used_nonces_mutant.rs")])
            self.assertEqual(len(hyps), 1)
            self.assertEqual(hyps[0]["covered_by"], "signature-replay")
            self.assertEqual(acc["covered_dedup"], 1)
            self.assertEqual(acc["hypotheses"], 0,
                             "covered hits are dropped from the needs-fuzz count")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_guard_predicate_is_load_bearing_nonvacuous(self):
        # Non-vacuity: disable the dominating-guard predicate and the CLEAN
        # (guarded) fixture must resurface as a false positive.
        orig = A4._uniq_dominating_guard
        try:
            A4._uniq_dominating_guard = lambda *a, **k: (False, None)
            emitted, _, _ = _scan("used_nonces_clean.rs")
            self.assertEqual(
                len(emitted), 1,
                "with the guard predicate off the clean case must fire")
        finally:
            A4._uniq_dominating_guard = orig

    def test_fp_predicate_is_load_bearing_nonvacuous(self):
        # Non-vacuity: disable the FP-guard and the monotone-counter fixture
        # must resurface.
        orig = A4._uniq_fp_suppressed
        try:
            A4._uniq_fp_suppressed = lambda *a, **k: (False, None)
            emitted, _, _ = _scan("counter_fp.rs")
            self.assertEqual(
                len(emitted), 1,
                "with the FP-guard off the monotone-counter case must fire")
        finally:
            A4._uniq_fp_suppressed = orig


if __name__ == "__main__":
    unittest.main()
