# <!-- r36-rebuttal: lane FIX-FCC-SCOPE-AUTHORITATIVE registered via agent-pathspec-register.py -->
"""Guard: function-coverage-completeness honors the authoritative in-scope manifest
(.auditooor/inscope_units.jsonl) as its function denominator - OOS packages walked from
src_roots (kona/cannon/op-batcher/... on a monorepo) are dropped, not counted as untouched.
Backward-compatible: no manifest -> no filtering; env override disables."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "function-coverage-completeness.py"


def _load():
    spec = importlib.util.spec_from_file_location("function_coverage_completeness", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["function_coverage_completeness"] = m
    spec.loader.exec_module(m)
    return m


class FccScopeFilterTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir(parents=True)
        # in-scope contract
        (self.ws / "src" / "inscope").mkdir(parents=True)
        (self.ws / "src" / "inscope" / "InScope.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.15;\n"
            "contract InScope {\n"
            "  function moveFunds(address to, uint256 amt) external {}\n"
            "  function withdraw(uint256 amt) external {}\n"
            "}\n", encoding="utf-8")
        # OOS contract (e.g. kona/cannon/op-batcher equivalent)
        (self.ws / "src" / "oos").mkdir(parents=True)
        (self.ws / "src" / "oos" / "OutOfScope.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.15;\n"
            "contract OutOfScope {\n"
            "  function oosA(uint256 x) external {}\n"
            "  function oosB(uint256 y) external {}\n"
            "  function oosC(uint256 z) external {}\n"
            "}\n", encoding="utf-8")

    def _manifest(self):
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/inscope/InScope.sol", "function": "", "lang": "solidity"}) + "\n",
            encoding="utf-8")

    def test_oos_functions_dropped_when_manifest_present(self):
        self._manifest()
        res = self.m.evaluate(self.ws)
        sf = res.get("scope_filter", {})
        self.assertTrue(sf.get("applied"))
        self.assertEqual(sf.get("in_scope_files"), 1)
        # OOS contract's 3 functions must be dropped from the denominator
        self.assertGreaterEqual(sf.get("out_of_scope_functions_dropped", 0), 3)
        files = " ".join(f.get("file", "") for f in res.get("functions", []))
        self.assertIn("InScope.sol", files)
        self.assertNotIn("OutOfScope.sol", files)

    def test_no_manifest_no_filter(self):
        # no inscope_units.jsonl -> legacy behavior, both contracts counted
        res = self.m.evaluate(self.ws)
        self.assertFalse(res.get("scope_filter", {}).get("applied"))
        files = " ".join(f.get("file", "") for f in res.get("functions", []))
        self.assertIn("OutOfScope.sol", files)

    def test_env_override_disables_filter(self):
        self._manifest()
        os.environ["AUDITOOOR_FCC_NO_SCOPE_FILTER"] = "1"
        try:
            res = self.m.evaluate(self.ws)
            self.assertFalse(res.get("scope_filter", {}).get("applied"))
            files = " ".join(f.get("file", "") for f in res.get("functions", []))
            self.assertIn("OutOfScope.sol", files)
        finally:
            del os.environ["AUDITOOOR_FCC_NO_SCOPE_FILTER"]


if __name__ == "__main__":
    unittest.main(verbosity=2)
