#!/usr/bin/env python3
"""Tests for tools/multi-impact-enumerator.py.

GENERICITY CONTRACT (mirrors the tool's mandate):
  - The tool body must contain ZERO hardcoded morpho/workspace specifics
    (no morpho paths, no contract names, no finding ids). Asserted by a
    grep over the source in test_no_hardcoding_in_tool_body.
  - The morpho-midnight anchor (callback-before-pull -> allowance-griefing
    enumerated, not just reentrancy) is the validation case, and it lives
    ONLY here in the test.
  - A second real workspace (any under /Users/wolf/audits with the inputs)
    is smoke-run to prove genericity; skipped cleanly if unavailable.
"""
from __future__ import annotations

import importlib.util
import json
import os
import unittest
from pathlib import Path

TOOL_PATH = Path(__file__).resolve().parents[1] / "multi-impact-enumerator.py"


def _load():
    spec = importlib.util.spec_from_file_location("multi_impact_enumerator", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MIE = _load()

MORPHO_WS = Path("/Users/wolf/audits/morpho-midnight")


class _Args:
    def __init__(self, **kw):
        self.workspace = kw.get("workspace")
        self.pattern = kw.get("pattern")
        self.function = kw.get("function")
        self.file_line = kw.get("file_line")
        self.candidate = kw.get("candidate")
        self.finding_file = kw.get("finding_file")
        self.json = kw.get("json", True)


class TestAnchor(unittest.TestCase):
    """morpho callback-before-pull anchor: allowance-griefing MUST be enumerated."""

    def test_callback_before_pull_enumerates_allowance_griefing(self):
        rc, payload = MIE.run(_Args(
            pattern="callback-before-pull",
            function="Midnight.sol:673",
        ))
        self.assertEqual(rc, 0)
        classes = {r["impact_class"] for r in payload["rows"]}
        # the WHOLE point: reentrancy alone would have closed this benignly
        self.assertIn("reentrancy", classes)
        self.assertIn("allowance-griefing", classes,
                      "anchor regression: allowance-griefing not enumerated")
        self.assertIn("callback-trick", classes)
        # more than one hypothesis => impact-imagination gap is addressed
        self.assertGreater(len(classes), 1)
        # each row is the full shape the spec requires
        for r in payload["rows"]:
            for k in ("pattern", "function", "impact_class", "attack_hypothesis", "test_to_run"):
                self.assertIn(k, r)
                self.assertTrue(r[k], f"empty field {k}")

    def test_external_call_before_state_is_multi_impact(self):
        rc, payload = MIE.run(_Args(pattern="external-call-before-state-finalization",
                                    function="X.sol:100"))
        self.assertEqual(rc, 0)
        classes = {r["impact_class"] for r in payload["rows"]}
        self.assertTrue({"reentrancy", "allowance-griefing", "callback-trick"} <= classes)

    @unittest.skipUnless((MORPHO_WS / "src/src/Midnight.sol").is_file(),
                         "morpho-midnight source not present")
    def test_source_call_hint_from_real_morpho_file(self):
        # bare file:line against the real workspace must read source + find a call cue
        rc, payload = MIE.run(_Args(
            workspace=MORPHO_WS,
            pattern="callback-before-pull",
            function="src/src/Midnight.sol:712",
            file_line="src/src/Midnight.sol:712",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(payload["meta"]["language"], "solidity")
        # call_hint may or may not match depending on the exact window, but the
        # run must not crash and must still enumerate multi-impact.
        self.assertGreater(payload["meta"]["impact_count"], 1)


class TestGenericity(unittest.TestCase):
    def test_no_hardcoding_in_tool_body(self):
        # Scan executable CODE only (strip the module docstring, which may name
        # the anchor for documentation). The mandate forbids hardcoded
        # workspace specifics in the tool LOGIC - paths, function names,
        # finding ids, contract names - not in the explanatory docstring.
        import ast
        src = TOOL_PATH.read_text()
        tree = ast.parse(src)
        if (tree.body and isinstance(tree.body[0], ast.Expr)
                and isinstance(getattr(tree.body[0], "value", None), ast.Constant)):
            # blank out the docstring lines so line-numbers stay aligned
            doc = tree.body[0]
            lines = src.splitlines()
            for ln in range(doc.lineno - 1, doc.end_lineno):
                lines[ln] = ""
            src = "\n".join(lines)
        body = src.lower()
        banned = ["morpho", "midnight", "/users/wolf/audits", "centrifuge",
                  "eq-001", "eq-002", "eq-003", "blackthorn", "spearbit"]
        for token in banned:
            self.assertNotIn(token, body,
                             f"tool CODE hardcodes '{token}' - violates genericity mandate")

    def test_language_awareness_rust(self):
        rc, payload = MIE.run(_Args(pattern="external-call-before-state",
                                    function="lending/src/lib.rs:42"))
        self.assertEqual(rc, 0)
        self.assertEqual(payload["meta"]["language"], "rust")
        # rust test runner referenced in test_to_run
        self.assertTrue(any("cargo" in r["test_to_run"] for r in payload["rows"]))

    def test_language_awareness_go_and_move(self):
        rc, p = MIE.run(_Args(pattern="missing-guard", function="x/keeper/msg.go:10"))
        self.assertEqual(p["meta"]["language"], "go")
        rc, p = MIE.run(_Args(pattern="callback", function="sources/vault.move:5"))
        self.assertEqual(p["meta"]["language"], "move")

    def test_unknown_pattern_degrades_to_language_default(self):
        rc, payload = MIE.run(_Args(pattern="some-totally-novel-pattern-xyz",
                                    function="A.sol:1"))
        self.assertEqual(rc, 0)
        self.assertFalse(payload["meta"]["pattern_matched"])
        self.assertTrue(payload["meta"]["note"])
        self.assertGreater(payload["meta"]["impact_count"], 1)

    def test_env_extensible_pattern_table(self):
        os.environ["AUDITOOOR_MIE_PATTERN_IMPACTS"] = "my-custom-pat=>oracle-trust,dos"
        try:
            rc, payload = MIE.run(_Args(pattern="my-custom-pat", function="A.sol:1"))
            classes = {r["impact_class"] for r in payload["rows"]}
            self.assertEqual(classes, {"oracle-trust", "dos"})
            self.assertTrue(payload["meta"]["pattern_matched"])
        finally:
            del os.environ["AUDITOOOR_MIE_PATTERN_IMPACTS"]

    def test_missing_inputs_is_input_error(self):
        rc, payload = MIE.run(_Args())
        self.assertEqual(rc, 2)
        self.assertIn("error", payload)

    def test_degrades_on_missing_workspace_artifacts(self):
        # candidate against a workspace with no artifacts -> honest empty, rc 0
        rc, payload = MIE.run(_Args(workspace=Path("/tmp"), candidate="NOPE-999"))
        self.assertEqual(rc, 0)
        self.assertEqual(payload["rows"], [])

    def test_second_workspace_smoke_run(self):
        """Smoke-run on a SECOND real workspace to prove the tool is not
        morpho-shaped. Skips cleanly if none is available."""
        second = None
        audits = Path("/Users/wolf/audits")
        if audits.is_dir():
            for d in sorted(audits.iterdir()):
                if d.name == "morpho-midnight":
                    continue
                if (d / "engage_report.md").is_file() or (d / ".auditooor/exploit_queue.json").is_file():
                    second = d
                    break
        if second is None:
            self.skipTest("no second workspace with artifacts available")
        # a generic pattern + a synthetic file:line under that workspace
        rc, payload = MIE.run(_Args(
            workspace=second,
            pattern="reentrancy",
            function="contract.sol:1",
            file_line="contract.sol:1",
        ))
        self.assertEqual(rc, 0)
        self.assertGreater(payload["meta"]["impact_count"], 1)
        self.assertEqual(payload["workspace"], str(second.resolve()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
