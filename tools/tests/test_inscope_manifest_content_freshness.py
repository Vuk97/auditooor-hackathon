#!/usr/bin/env python3
# <!-- r36-rebuttal: lane INSCOPE-MANIFEST-CONTENT-FRESHNESS registered in commit message -->
"""Adversarial wiring-verify L1 (2026-06-30): write_inscope_manifest's freshness gate was
mtime-only, so a STALE manifest (fewer files than the scope now resolves to) was pinned forever
because its mtime was already >= the source mtime. After a scope_exclusion fix un-dropped 2
interface files, strata's manifest stayed at 17 files instead of 19. Fix: the gate is now
content-aware - it regenerates when the manifest's distinct file-set does not cover the current
in-scope source file-set. Pin: a manifest missing an expected in-scope file triggers regen.
"""
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "workspace-coverage-heatmap.py"


def _load():
    spec = importlib.util.spec_from_file_location("wch", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["wch"] = m
    spec.loader.exec_module(m)
    return m


wch = _load()


class InscopeManifestContentFreshnessTest(unittest.TestCase):
    def _ws(self):
        ws = Path(tempfile.mkdtemp(prefix="wch_"))
        src = ws / "src"
        (src / "a").mkdir(parents=True)
        (src / "b").mkdir(parents=True)
        (src / "a" / "Foo.sol").write_text(
            "// SPDX\npragma solidity ^0.8.0;\ncontract Foo { function f() external {} }\n",
            encoding="utf-8")
        (src / "b" / "Bar.sol").write_text(
            "// SPDX\npragma solidity ^0.8.0;\ncontract Bar { function g() external {} }\n",
            encoding="utf-8")
        (ws / "SCOPE.md").write_text("# SCOPE\n## In scope\nWhole repo.\n", encoding="utf-8")
        (ws / ".auditooor").mkdir()
        return ws

    def test_stale_undercount_manifest_regenerates(self):
        ws = self._ws()
        mf = ws / ".auditooor" / "inscope_units.jsonl"
        # write a STALE manifest covering only Foo.sol (missing Bar.sol), with a
        # FUTURE mtime so the mtime-only gate would have kept it.
        mf.write_text(json.dumps({"file": "src/a/Foo.sol", "name": "f"}) + "\n",
                      encoding="utf-8")
        import os
        future = time.time() + 10_000
        os.utime(mf, (future, future))
        out, rows, wrote = wch.write_inscope_manifest(ws)
        files = {json.loads(l)["file"].rsplit("/", 1)[-1]
                 for l in mf.read_text().splitlines() if l.strip()}
        # content-aware gate must have regenerated to include the missing Bar.sol
        self.assertIn("Bar.sol", files)
        self.assertIn("Foo.sol", files)
        self.assertTrue(wrote)

    def test_same_basename_in_different_directories_is_not_collapsed(self):
        ws = self._ws()
        second = ws / "src" / "b" / "Foo.sol"
        second.write_text(
            "pragma solidity ^0.8.0; contract Other { function other() external {} }\n",
            encoding="utf-8")
        manifest, _, wrote = wch.write_inscope_manifest(ws)
        self.assertTrue(wrote)
        rows = [json.loads(line) for line in manifest.read_text().splitlines() if line]
        paths = {row["file"] for row in rows}
        self.assertIn("src/a/Foo.sol", paths)
        self.assertIn("src/b/Foo.sol", paths)

    def test_function_edit_and_file_add_remove_regenerate(self):
        ws = self._ws()
        manifest, _, _ = wch.write_inscope_manifest(ws)
        (ws / "src" / "a" / "Foo.sol").write_text(
            "pragma solidity ^0.8.0; contract Foo { function changed() external {} }\n",
            encoding="utf-8")
        _, _, wrote = wch.write_inscope_manifest(ws)
        self.assertTrue(wrote)
        rows = [json.loads(line) for line in manifest.read_text().splitlines() if line]
        self.assertIn("changed", {row["function"] for row in rows})
        added = ws / "src" / "new" / "Added.sol"
        added.parent.mkdir()
        added.write_text("pragma solidity ^0.8.0; contract Added { function x() external {} }\n", encoding="utf-8")
        _, _, wrote = wch.write_inscope_manifest(ws)
        self.assertTrue(wrote)
        added.unlink()
        _, _, wrote = wch.write_inscope_manifest(ws)
        self.assertTrue(wrote)
        self.assertNotIn("src/new/Added.sol", {json.loads(line)["file"] for line in manifest.read_text().splitlines() if line})

    def test_scope_change_regenerates(self):
        ws = self._ws()
        manifest, _, _ = wch.write_inscope_manifest(ws)
        (ws / "scope.json").write_text(json.dumps({"in_scope": ["src/a/Foo.sol"]}), encoding="utf-8")
        _, _, wrote = wch.write_inscope_manifest(ws)
        self.assertTrue(wrote)
        self.assertEqual({json.loads(line)["file"] for line in manifest.read_text().splitlines() if line}, {"src/a/Foo.sol"})

    def test_oscript_change_regenerates(self):
        ws = self._ws()
        aa = ws / "src" / "agent.aa"
        aa.write_text("{ messages: [ { app: 'payment', payload: {} } ] }\n", encoding="utf-8")
        manifest, _, _ = wch.write_inscope_manifest(ws)
        before = manifest.read_text(encoding="utf-8")
        aa.write_text("{ init: `{ $x = 1; }`, messages: [ { app: 'payment', payload: {} } ] }\n", encoding="utf-8")
        _, _, wrote = wch.write_inscope_manifest(ws)
        self.assertTrue(wrote)
        self.assertNotEqual(before, manifest.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
