#!/usr/bin/env python3
"""Regression test: hunt-coverage-gate credits the NATURAL top-level hunt-sidecar
schema ({file, function, verdict}), not only the nested function_anchor schema.

Serving-join false-red surfaced on near-intents 2026-06-26: per-fn hunt agents
write {task_id, file, line, function, verdict, ...} at top level; the gate's
_review_token_source_record only read target/reviewed_units/source_citations/
function_anchor, so 265 genuine hunt sidecars credited ~0 units. The fix reads
the top-level file+function (verdict-gated, function-precise).
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "hunt-coverage-gate.py"
_spec = importlib.util.spec_from_file_location("hcg_tl", _TOOL)
hcg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hcg)


class TopLevelSchemaTest(unittest.TestCase):
    def _write(self, tmp, obj):
        p = Path(tmp) / "sc.json"
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def test_toplevel_file_function_verdict_credits(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, {
                "task_id": "t1",
                "file": "src/btc-bridge/contracts/satoshi-bridge/src/refund.rs",
                "line": 496, "function": "request_refund_callback",
                "verdict": "REFUTED",
            })
            rec = hcg._review_token_source_record(p, "")
            self.assertIsNotNone(rec)
            toks = rec["tokens"]
            self.assertTrue(any("::request_refund_callback" in t for t in toks),
                            f"expected fn token, got {toks}")

    def test_no_verdict_signal_does_not_credit(self):
        # a raw, un-adjudicated row (no verdict/disposition) must NOT count
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, {
                "task_id": "t2",
                "file": "src/x/lib.rs", "function": "foo",
            })
            rec = hcg._review_token_source_record(p, "")
            self.assertIsNone(rec)

    def test_function_with_signature_paren_stripped(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, {
                "file": "OmniBridge.sol", "function": "finTransfer(bytes,tuple)",
                "verdict": "REFUTED",
            })
            rec = hcg._review_token_source_record(p, "")
            self.assertIsNotNone(rec)
            self.assertTrue(any(t.endswith("::finTransfer") for t in rec["tokens"]),
                            f"paren not stripped: {rec['tokens']}")

    def test_placeholder_anchor_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, {"file": "?", "function": "?", "verdict": "REFUTED"})
            rec = hcg._review_token_source_record(p, "")
            self.assertIsNone(rec)

    def test_nested_function_anchor_still_works(self):
        # the pre-existing nested schema must remain functional
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, {
                "function_anchor": {"file": "src/x/lib.rs", "function": "bar"},
                "verdict": "REFUTED",
            })
            rec = hcg._review_token_source_record(p, "")
            self.assertIsNotNone(rec)
            self.assertTrue(any("::bar" in t for t in rec["tokens"]))


if __name__ == "__main__":
    unittest.main()
