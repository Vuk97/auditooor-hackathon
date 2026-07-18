#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "claim-precondition-check.py"


def load_tool():
    name = "_claim_precondition_check_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ClaimPreconditionCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def test_no_directives_passes(self) -> None:
        directives = self.tool.parse_directives("# Draft\n")
        rc, messages, entries = self.tool.evaluate(
            directives, observed={}, rpc_url=None, skip_live_verify=False
        )
        self.assertEqual(rc, 0)
        self.assertEqual(messages, [])
        self.assertEqual(entries, [])

    def test_observed_json_match_passes(self) -> None:
        text = "<!-- claim-precondition: feeModule.paused() == false -->"
        directives = self.tool.parse_directives(text)
        rc, messages, entries = self.tool.evaluate(
            directives,
            observed={"feeModule.paused()": "false"},
            rpc_url=None,
            skip_live_verify=False,
        )
        self.assertEqual(rc, 0, messages)
        self.assertEqual(entries[0]["status"], "match")

    def test_observed_json_contradiction_fails(self) -> None:
        text = "<!-- claim-precondition: feeModule.paused() == false -->"
        directives = self.tool.parse_directives(text)
        rc, messages, entries = self.tool.evaluate(
            directives,
            observed={"feeModule.paused()": "true"},
            rpc_url=None,
            skip_live_verify=False,
        )
        self.assertEqual(rc, 1)
        self.assertIn("contradicted", "\n".join(messages))
        self.assertEqual(entries[0]["status"], "contradicts")

    def test_unresolved_directive_warns(self) -> None:
        text = "<!-- claim-precondition: feeModule.paused() == false -->"
        directives = self.tool.parse_directives(text)
        rc, messages, entries = self.tool.evaluate(
            directives, observed={}, rpc_url=None, skip_live_verify=False
        )
        self.assertEqual(rc, 2)
        self.assertIn("no observed value", "\n".join(messages))
        self.assertEqual(entries[0]["status"], "cannot-run")

    def test_cli_with_observed_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            draft = Path(td) / "draft.md"
            observed = Path(td) / "observed.json"
            draft.write_text("<!-- claim-precondition: x.owner() == 0x0000000000000000000000000000000000000001 -->")
            observed.write_text(json.dumps({"x.owner()": "0x0000000000000000000000000000000000000001"}))
            rc = self.tool.main([str(draft), "--observed-json", str(observed)])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
