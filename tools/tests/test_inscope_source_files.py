#!/usr/bin/env python3
"""Guard: inscope-source-files.py emits ONLY in-scope source paths from the
authoritative .auditooor/inscope_units.jsonl manifest - the generic scope source
that the EVM engine-harness author (audit-deep-solidity) now enumerates from, so
out-of-scope modules declared in scope.json (e.g. Hyperlane's contracts/avs) are
never harnessed. Falls back (rc=1, no stdout) when no manifest exists so the
caller can use its legacy find."""
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "inscope-source-files.py"


def _load():
    spec = importlib.util.spec_from_file_location("inscope_source_files", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["inscope_source_files"] = m
    spec.loader.exec_module(m)
    return m


class InscopeSourceFilesTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True)

    def _write_manifest(self, rows):
        (self.tmp / ".auditooor" / "inscope_units.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    def test_emits_only_inscope_sol_paths(self):
        # the manifest is already scope-filtered - it simply must not invent OOS
        self._write_manifest([
            {"file": "src/solidity/contracts/Mailbox.sol", "function": "dispatch"},
            {"file": "src/solidity/contracts/client/GasRouter.sol", "function": "quoteGasPayment"},
            {"file": "src/op-node/derive.go", "function": "x"},  # non-sol filtered by --ext
        ])
        files = self.m.inscope_files(self.tmp, ext=".sol")
        names = [p.name for p in files]
        self.assertIn("Mailbox.sol", names)
        self.assertIn("GasRouter.sol", names)
        self.assertNotIn("derive.go", names)
        # absolute, resolved against the workspace
        for p in files:
            self.assertTrue(p.is_absolute())
            self.assertTrue(str(p).startswith(str(self.tmp)))

    def test_oos_avs_not_emitted_when_absent_from_manifest(self):
        # avs is OOS per scope.json so it is NOT in inscope_units.jsonl; the
        # helper must not resurrect it (the harness-author avs scope-leak).
        self._write_manifest([
            {"file": "src/solidity/contracts/Mailbox.sol", "function": "dispatch"},
        ])
        names = [p.name for p in self.m.inscope_files(self.tmp, ext=".sol")]
        self.assertEqual(names, ["Mailbox.sol"])
        self.assertNotIn("ECDSAServiceManagerBase.sol", names)

    def test_dedup_and_sorted(self):
        self._write_manifest([
            {"file": "src/B.sol", "function": "f1"},
            {"file": "src/A.sol", "function": "f2"},
            {"file": "src/B.sol", "function": "f3"},  # dup file, different fn
        ])
        names = [p.name for p in self.m.inscope_files(self.tmp, ext=".sol")]
        self.assertEqual(names, ["A.sol", "B.sol"])

    def test_no_manifest_returns_empty_and_rc1(self):
        empty_ws = Path(tempfile.mkdtemp())
        self.assertEqual(self.m.inscope_files(empty_ws, ext=".sol"), [])
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.m.main([str(empty_ws), "--ext", ".sol"])
        self.assertEqual(rc, 1)
        self.assertEqual(buf.getvalue().strip(), "")  # no stdout -> caller falls back

    def test_main_prints_paths_rc0(self):
        self._write_manifest([{"file": "src/Mailbox.sol", "function": "dispatch"}])
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.m.main([str(self.tmp), "--ext", ".sol"])
        self.assertEqual(rc, 0)
        self.assertIn("Mailbox.sol", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
