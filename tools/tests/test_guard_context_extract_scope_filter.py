#!/usr/bin/env python3
"""Guard tests for guard-context-extract.py scope + test-module filtering.

Regression for the optimism depth-probe pollution: ~48% (910/1905) of guard
probe packets were Rust ``#[cfg(test)]`` test assertions (op-reth flashblocks),
burning LLM probe budget on test oracles instead of production guards. The
extractor must drop (a) guards in OOS files (manifest-authoritative is_in_scope)
and (b) guards inside Rust ``#[cfg(test)]`` / ``#[test]`` items.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "guard-context-extract.py"
_spec = importlib.util.spec_from_file_location("gce", _TOOL)
gce = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gce)


class TestRangeDetector(unittest.TestCase):
    def test_prod_guard_not_marked_test(self):
        src = (
            "pub fn prod(x: u64) -> u64 {\n"
            "    assert!(x > 0);\n"
            "    x + 1\n"
            "}\n"
        ).splitlines()
        tr = gce._test_line_ranges(src)
        self.assertNotIn(1, tr, "production assert! mis-marked as test")

    def test_cfg_test_mod_marked(self):
        src = (
            "pub fn prod() {}\n"
            "\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    #[test]\n"
            "    fn t() {\n"
            "        assert_eq!(1, 1);\n"
            "    }\n"
            "}\n"
        ).splitlines()
        tr = gce._test_line_ranges(src)
        self.assertIn(6, tr, "test assert_eq! not marked as test")
        self.assertIn(3, tr, "mod tests body not marked as test")
        self.assertNotIn(0, tr, "production fn mis-marked as test")

    def test_cfg_test_use_not_overmarked(self):
        # A `#[cfg(test)] use ...;` is non-braced; must NOT swallow a later item.
        src = (
            "#[cfg(test)]\n"
            "use super::*;\n"
            "\n"
            "pub fn prod() {\n"
            "    let y = 1;\n"
            "}\n"
        ).splitlines()
        tr = gce._test_line_ranges(src)
        self.assertNotIn(4, tr, "production fn body swallowed by a #[cfg(test)] use")


class ExtractScopeFilterTest(unittest.TestCase):
    def _ws(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / "src").mkdir()
        return ws

    def test_test_module_guard_skipped(self):
        ws = self._ws()
        src = (
            "pub fn validate(x: u64) -> bool {\n"
            "    if x == 0 { return false; }\n"
            "    true\n"
            "}\n"
            "\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    #[test]\n"
            "    fn t() {\n"
            "        assert!(validate(1));\n"
            "    }\n"
            "}\n"
        )
        (ws / "src" / "lib.rs").write_text(src, encoding="utf-8")
        wl = ws / ".auditooor" / "negative_space_worklist.jsonl"
        wl.write_text(
            json.dumps({"guard_id": "G1", "file_line": "src/lib.rs:2",
                        "checks": "if x == 0", "invariant_hint": "non-zero"}) + "\n"
            + json.dumps({"guard_id": "G2", "file_line": "src/lib.rs:10",
                          "checks": "assert!(validate(1))", "invariant_hint": "test"}) + "\n",
            encoding="utf-8",
        )
        out = ws / ".auditooor" / "guard_probe_packets.jsonl"
        res = gce.extract(ws, ws, window=40, limit=None, out_path=out)
        self.assertEqual(res["packets_written"], 1, "expected only the production guard")
        self.assertEqual(res["test_skipped"], 1, "test-module guard not skipped")
        written = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        self.assertEqual(written[0]["guard_id"], "G1")


if __name__ == "__main__":
    unittest.main()
