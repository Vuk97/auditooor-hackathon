"""Unit tests for Rule 78 load-bearing-assumption-audit (umbrella meta-gate).

Anchor: zebra batch over-claim (2026-06-02). A HIGH finding's amplification
rested on TWO unverified assumptions - (a) jsonrpsee processes a JSON-RPC batch
concurrently, (b) the batch is unbounded by default. Neither was recognised as
an assumption, so neither was written down. R78 forces a Load-Bearing
Assumption Ledger to exist so both surface at brief time; the corrected finding
cites jsonrpsee-server-0.24.10/src/server.rs:1318 + max_connections=100 default.

R78 composes with R76/R77/R42/R46 - it enforces the ledger EXISTS + is complete;
the sibling gates verify specific assumption classes.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "load-bearing-assumption-audit-check.py"
_spec = importlib.util.spec_from_file_location(
    "load_bearing_assumption_audit_check", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _write(body: str, *, filename: str = "draft-HIGH.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="r78_ledger_"))
    draft = root / filename
    draft.write_text(body, encoding="utf-8")
    return draft


# --- ANCHOR: zebra HIGH, NO ledger -> the assumptions were never written down
ZEBRA_NO_LEDGER = """Severity: High

## Summary
A single unauthenticated HTTP JSON-RPC batch amplifies into K concurrent wallet
scans, exhausting CPU on the node.

## Details
One batch fans out so each call is processed concurrently by jsonrpsee, and the
batch size is unbounded, so a 5000-call batch launches 5000 concurrent scans.
"""

# --- ANCHOR corrected: zebra HIGH, ledger WITH the jsonrpsee + default rows
ZEBRA_LEDGER_COMPLETE = """Severity: High

## Summary
A single unauthenticated HTTP JSON-RPC batch fans out into K scans.

## Load-Bearing Assumption Ledger

| # | Assumption | Class | How verified | Source |
|---|-----------|-------|--------------|--------|
| 1 | jsonrpsee processes a batch concurrently | external-dep-behavior | read crate source | ~/.cargo/registry/.../jsonrpsee-server-0.24.10/src/server.rs:1318 (sequential for-loop - claim bounded) |
| 2 | batch size unbounded by default | external-library-default | read server config default | max_connections=100 default in jsonrpsee ServerBuilder |
| 3 | scan endpoint reachable unauthenticated | in-tree-source | grepped router | rpc/src/methods.rs:88 |

## Details
The amplification is bounded once both assumptions are verified.
"""

# --- HIGH ledger present, one row UNVERIFIED, no inline rebuttal -> FAIL
LEDGER_UNVERIFIED = """Severity: High

## Load-Bearing Assumption Ledger

| # | Assumption | Class | How verified | Source |
|---|-----------|-------|--------------|--------|
| 1 | pool has non-zero liquidity at attack time | deployment-config | UNVERIFIED | - |
| 2 | function reachable by any caller | in-tree-source | grepped access control | Vault.sol:120 |
"""

# --- HIGH ledger present, UNVERIFIED row carries inline rebuttal -> PASS
LEDGER_UNVERIFIED_REBUTTALED = """Severity: High

## Load-Bearing Assumption Ledger

| # | Assumption | Class | How verified | Source |
|---|-----------|-------|--------------|--------|
| 1 | external chain finalizes in <2 blocks | protocol-version-semantics | UNVERIFIED - r78-unverified-rebuttal: bounded by program OOS clause, accepted-risk | program SCOPE.md:40 |
| 2 | router configured in production | config-cited | read deploy config | deploy/mainnet.json:12 |
"""

# --- HIGH ledger heading present but NO data rows -> FAIL
LEDGER_HEADING_NO_ROWS = """Severity: High

## Load-Bearing Assumption Ledger

(to be filled in)

## Details
Body here.
"""

# --- MEDIUM finding -> out of scope (R78 fires HIGH+ only)
MEDIUM_FINDING = """Severity: Medium

## Summary
A rounding issue. No ledger needed because below HIGH.
"""

# --- HIGH with draft-level r78-rebuttal -> ok-rebuttal
HIGH_REBUTTAL = """Severity: High

<!-- r78-rebuttal: source-only finding, single in-tree assumption stated in body -->

## Summary
A reentrancy in Vault.withdraw at Vault.sol:88.
"""

# --- HIGH, complete ledger, alternate heading "Assumption Ledger" -> PASS
ALT_HEADING_COMPLETE = """Severity: High

## Assumption Ledger

| Assumption | Class | How verified | Source |
|-----------|-------|--------------|--------|
| caller can be any EOA | in-tree-source | grepped | Mod.rs:10 |
"""


class TestR78LoadBearingAssumptionAudit(unittest.TestCase):
    def _run(self, body, **kw):
        draft = _write(body, **{k: v for k, v in kw.items() if k == "filename"})
        sev = kw.get("severity")
        rc, payload = mod.run(draft, severity_override=sev)
        return rc, payload

    # 1. ANCHOR: zebra HIGH, no ledger -> FAIL
    def test_zebra_no_ledger_fails(self):
        rc, p = self._run(ZEBRA_NO_LEDGER)
        self.assertEqual(rc, 1)
        self.assertEqual(p["verdict"], "fail-no-assumption-ledger")

    # 2. ANCHOR corrected: zebra HIGH, complete ledger -> PASS
    def test_zebra_ledger_complete_passes(self):
        rc, p = self._run(ZEBRA_LEDGER_COMPLETE)
        self.assertEqual(rc, 0)
        self.assertEqual(p["verdict"], "pass-assumption-ledger-complete")
        self.assertGreaterEqual(p["evidence"]["data_row_count"], 3)

    # 3. ledger with an UNVERIFIED row, no inline rebuttal -> FAIL
    def test_unverified_row_fails(self):
        rc, p = self._run(LEDGER_UNVERIFIED)
        self.assertEqual(rc, 1)
        self.assertEqual(p["verdict"], "fail-unverified-load-bearing-assumption")
        self.assertEqual(len(p["evidence"]["unverified_rows"]), 1)

    # 4. UNVERIFIED row WITH inline rebuttal -> PASS
    def test_unverified_row_rebuttaled_passes(self):
        rc, p = self._run(LEDGER_UNVERIFIED_REBUTTALED)
        self.assertEqual(rc, 0)
        self.assertEqual(p["verdict"],
                         "pass-assumption-ledger-unverified-rebuttaled")

    # 5. heading present but no data rows -> FAIL
    def test_heading_no_rows_fails(self):
        rc, p = self._run(LEDGER_HEADING_NO_ROWS)
        self.assertEqual(rc, 1)
        self.assertEqual(p["verdict"], "fail-no-assumption-ledger")

    # 6. MEDIUM -> out of scope
    def test_medium_out_of_scope(self):
        rc, p = self._run(MEDIUM_FINDING)
        self.assertEqual(rc, 0)
        self.assertEqual(p["verdict"], "pass-out-of-scope")

    # 7. draft-level rebuttal -> ok-rebuttal
    def test_draft_level_rebuttal(self):
        rc, p = self._run(HIGH_REBUTTAL)
        self.assertEqual(rc, 0)
        self.assertEqual(p["verdict"], "ok-rebuttal")

    # 8. alternate heading recognised -> PASS
    def test_alt_heading_complete(self):
        rc, p = self._run(ALT_HEADING_COMPLETE)
        self.assertEqual(rc, 0)
        self.assertEqual(p["verdict"], "pass-assumption-ledger-complete")

    # 9. severity from filename when no header -> HIGH fires
    def test_severity_from_filename_high(self):
        body = "## Summary\nNo severity header here."
        draft = _write(body, filename="finding-HIGH.md")
        rc, p = mod.run(draft, severity_override="auto")
        self.assertEqual(rc, 1)
        self.assertEqual(p["verdict"], "fail-no-assumption-ledger")

    # 10. CRITICAL also fires
    def test_critical_fires(self):
        rc, p = self._run("Severity: Critical\n\n## Summary\nNo ledger.")
        self.assertEqual(rc, 1)
        self.assertEqual(p["verdict"], "fail-no-assumption-ledger")

    # 11. composition metadata is present (delegate, not duplicate)
    def test_composition_metadata(self):
        rc, p = self._run(ZEBRA_LEDGER_COMPLETE)
        self.assertIn("R76", p["composes_with"])
        self.assertIn("R77", p["composes_with"])
        self.assertIn("R42", p["composes_with"])
        self.assertIn("R46", p["composes_with"])

    # 12. JSON output is valid + schema-tagged via CLI
    def test_cli_json_schema(self):
        draft = _write(ZEBRA_NO_LEDGER)
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(draft), "--json"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"],
                         "auditooor.r78_load_bearing_assumption_audit.v1")
        self.assertEqual(payload["gate"], "R78-LOAD-BEARING-ASSUMPTION-AUDIT")

    # 13. error on unreadable file
    def test_error_missing_file(self):
        rc, p = mod.run(Path("/nonexistent/r78/does-not-exist.md"),
                        severity_override="high")
        self.assertEqual(rc, 2)
        self.assertEqual(p["verdict"], "error")

    # 14. env hook: custom UNVERIFIED marker recognised
    def test_env_unverified_pattern(self):
        import os
        body = """Severity: High

## Load-Bearing Assumption Ledger

| Assumption | Class | How verified | Source |
|-----------|-------|--------------|--------|
| x behaves | external-dep-behavior | GUESSED | - |
"""
        draft = _write(body)
        os.environ["AUDITOOOR_R78_UNVERIFIED_PATTERNS"] = "GUESSED"
        try:
            rc, p = mod.run(draft, severity_override="high")
        finally:
            del os.environ["AUDITOOOR_R78_UNVERIFIED_PATTERNS"]
        self.assertEqual(rc, 1)
        self.assertEqual(p["verdict"], "fail-unverified-load-bearing-assumption")


if __name__ == "__main__":
    unittest.main()
