#!/usr/bin/env python3
# <!-- r36-rebuttal: lane L37-G15-FUNCTION-ANCHOR-FIX registered via agent-pathspec-register.py -->
"""Guard: hunt-coverage-gate credits an ADJUDICATED spawn-worker hunt sidecar
(function_anchor {file, function} + a verdict/applies_to_target signal) as
per-function SCAN evidence, for BOTH the dict-form ``result`` (spawn-worker
Sonnet schema) and the nested JSON-string ``result`` (MIMO/haiku schema).

Regression for the beanstalk g15 false-red: a detector-flagged unit that WAS
genuinely hunted (source-cited FP-defended) scored detector-only/queued-not-
scanned because _review_token_source_record only recognised target/
reviewed_units/source_citations, not the canonical per-function hunt schema.
A raw un-adjudicated seed (no signal) must NOT count.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("g15_under_test", str(_TOOLS / "hunt-coverage-gate.py"))
g15 = importlib.util.module_from_spec(spec)
sys.modules["g15_under_test"] = g15
spec.loader.exec_module(g15)


def _sidecar(tmp: Path, name: str, obj: dict) -> Path:
    p = tmp / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


class TestG15FunctionAnchorScan(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _anchor(self, fn="permitERC20"):
        return {"file": "src/beanstalk/protocol/contracts/beanstalk/farm/TokenSupportFacet.sol",
                "function": fn, "line": 32}

    def test_dict_result_anchor_counts_as_scan(self):
        p = _sidecar(self.tmp, "a.json", {
            "function_anchor": self._anchor(),
            "status": "ok",
            "result": {"applies_to_target": "no", "candidate_finding": "permit bound to owner"},
        })
        rec = g15._review_token_source_record(p, "")
        self.assertIsNotNone(rec, "dict-result function_anchor sidecar must be a scan source")
        self.assertTrue(any("permitERC20" in t for t in rec["tokens"]))

    def test_string_result_anchor_counts_as_scan(self):
        p = _sidecar(self.tmp, "b.json", {
            "function_anchor": self._anchor("permitERC721"),
            "status": "ok",
            "result": json.dumps({"applies_to_target": "no", "candidate_finding": "sig bound"}),
        })
        rec = g15._review_token_source_record(p, "")
        self.assertIsNotNone(rec, "string-result function_anchor sidecar must be a scan source")
        self.assertTrue(any("permitERC721" in t for t in rec["tokens"]))

    def test_unadjudicated_anchor_not_counted(self):
        # function_anchor present but NO verdict/applies_to_target signal -> raw seed.
        p = _sidecar(self.tmp, "c.json", {
            "function_anchor": self._anchor("transferERC1155"),
            "status": "ok",
            "result": {"note": "not yet investigated"},
        })
        rec = g15._review_token_source_record(p, "")
        self.assertIsNone(rec, "an un-adjudicated anchor sidecar must NOT count as scan evidence")

    def test_placeholder_anchor_not_counted(self):
        # the MIMO/haiku placeholder anchor (file='?', fn='?') must not map.
        p = _sidecar(self.tmp, "d.json", {
            "function_anchor": {"file": "?", "fn": "?", "start_line": 0, "end_line": 0},
            "status": "ok",
            "result": json.dumps({"applies_to_target": "no"}),
        })
        rec = g15._review_token_source_record(p, "")
        self.assertIsNone(rec, "a placeholder '?' anchor must not produce a unit token")

    def test_filename_slug_fallback_counts_as_scan(self):
        # FILENAME-FALLBACK REGRESSION (NUVA residual-80 2026-07-03): a disposition
        # sidecar with NO function_anchor and NO top-level file/fn - the unit identity
        # lives ONLY in the double-encoded ``result`` string and the canonical slug
        # filename hunt__<file>__<fn>__... - must still credit its unit.
        p = _sidecar(self.tmp, "hunt__CrossChainManager.sol__constructor__de0caac8__I-generic.json", {
            "status": "ok",
            "result": json.dumps({
                "applies_to_target": "no",
                "file_line": "src/nuva-evm-contracts/contracts/CrossChainManager.sol:204",
                "code_excerpt": "constructor() { _disableInitializers(); }",
            }),
        })
        rec = g15._review_token_source_record(p, "")
        self.assertIsNotNone(rec, "filename-slug sidecar (no anchor) must be a scan source")
        self.assertTrue(any("CrossChainManager.sol::constructor" in t for t in rec["tokens"]),
                        f"expected CrossChainManager.sol::constructor in {rec['tokens'] if rec else None}")

    def test_filename_slug_fallback_requires_signal(self):
        # An un-adjudicated filename-slug sidecar (no verdict/applies_to_target) must
        # NOT count - the slug alone is not evidence.
        p = _sidecar(self.tmp, "hunt__Foo.sol__bar__deadbeef__I-generic.json", {
            "status": "ok",
            "result": json.dumps({"note": "not yet investigated"}),
        })
        rec = g15._review_token_source_record(p, "")
        self.assertIsNone(rec, "a filename-slug sidecar with no adjudication signal must not count")


if __name__ == "__main__":
    unittest.main(verbosity=2)
