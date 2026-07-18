#!/usr/bin/env python3
"""Guard: hunt-completeness check_audit_deep recognizes the CURRENT canonical
deep-manifest paths, not only the legacy .audit_logs/audit_deep*_manifest.json glob
(the SSV serving-gap: audit-deep ran + wrote .auditooor/solidity-deep-audit/
manifest.json, but hunt-complete reported no-audit-deep)."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "hunt_completeness_check", str(_TOOLS / "hunt-completeness-check.py"))
hcc = importlib.util.module_from_spec(_spec)
sys.modules["hunt_completeness_check"] = hcc  # so @dataclass can resolve the module
_spec.loader.exec_module(hcc)


class TestAuditDeepSignal(unittest.TestCase):
    def test_canonical_solidity_deep_manifest_recognized(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor" / "solidity-deep-audit").mkdir(parents=True)
        (ws / ".auditooor" / "solidity-deep-audit" / "manifest.json").write_text("{}")
        r = hcc.check_audit_deep(ws)
        self.assertTrue(r.ok, r.reason)

    def test_all_harnesses_manifest_recognized(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".audit_logs").mkdir(parents=True)
        (ws / ".audit_logs" / "solidity_deep_all_harnesses_manifest.json").write_text("{}")
        self.assertTrue(hcc.check_audit_deep(ws).ok)

    def test_legacy_glob_still_recognized(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".audit_logs").mkdir(parents=True)
        (ws / ".audit_logs" / "audit_deep_go_manifest.json").write_text("{}")
        self.assertTrue(hcc.check_audit_deep(ws).ok)

    def test_empty_workspace_still_fails(self):
        ws = Path(tempfile.mkdtemp())
        self.assertFalse(hcc.check_audit_deep(ws).ok)


if __name__ == "__main__":
    unittest.main()
