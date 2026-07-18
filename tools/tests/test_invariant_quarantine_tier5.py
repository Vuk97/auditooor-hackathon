"""Test LANE-190 quarantine of 501 FP-deepseek-mined invariants to tier-5.

r36-rebuttal: lane registered as lane-LANE-190-TIER5-QUARANTINE via tools/agent-pathspec-register.py register --lane lane-LANE-190-TIER5-QUARANTINE --files tools/tests/test_invariant_quarantine_tier5.py,audit/corpus_tags/derived/invariants_pilot_audited.jsonl,audit/corpus_tags/derived/invariants_quarantine_tier5.jsonl,audit/corpus_tags/derived/invariants_pilot_audited.jsonl.bak.pre-quarantine-2026-05-26 --ttl 5400 (registered 2026-05-26T18:12Z)

Verifies the corpus split per R37 verification_tier discipline:
- invariants_quarantine_tier5.jsonl: 501 records, all tier-5-quarantine, all audit_verdict=FALSE-POSITIVE
- invariants_pilot_audited.jsonl: 1045 records, 0 tier-5, 0 FP leak
- vault_invariant_library default: 0 tier-5 returned
- vault_invariant_library min_verification_tier=5: tier-5 still blocked by _quality_passed (defense-in-depth)
- Check #72 (hackerman-record-verification-tier-check.py) exists and references tier-5 quarantine
- Backup file exists
"""
from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DERIVED = ROOT / "audit" / "corpus_tags" / "derived"
PILOT = DERIVED / "invariants_pilot_audited.jsonl"
QUAR = DERIVED / "invariants_quarantine_tier5.jsonl"
BACKUP = DERIVED / "invariants_pilot_audited.jsonl.bak.pre-quarantine-2026-05-26"
MCP = ROOT / "tools" / "vault-mcp-server.py"
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"
HKVT_TOOL = ROOT / "tools" / "hackerman-record-verification-tier-check.py"


def _iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                yield json.loads(s)
            except json.JSONDecodeError:
                continue


class TestInvariantQuarantineTier5(unittest.TestCase):
    def test_quarantine_file_501_records_all_tier5(self):
        self.assertTrue(QUAR.exists(), f"quarantine file missing: {QUAR}")
        rows = list(_iter_jsonl(QUAR))
        self.assertEqual(len(rows), 501, "expected 501 quarantine records")
        for r in rows:
            self.assertEqual(
                r.get("verification_tier"),
                "tier-5-quarantine",
                f"non-tier-5 record in quarantine: {r.get('invariant_id') or r.get('source_id')}",
            )
            verdict = (r.get("audit_verdict") or "").upper()
            self.assertIn("FALSE", verdict, "quarantine record missing FALSE-POSITIVE verdict")

    def test_pilot_audited_1045_records_no_tier5_no_fp(self):
        self.assertTrue(PILOT.exists(), f"pilot file missing: {PILOT}")
        rows = list(_iter_jsonl(PILOT))
        self.assertEqual(len(rows), 1045, "expected 1045 records remaining after quarantine")
        tier5_leak = sum(1 for r in rows if str(r.get("verification_tier", "")).startswith("tier-5"))
        self.assertEqual(tier5_leak, 0, "tier-5 leaked into pilot_audited")
        fp_leak = sum(1 for r in rows if "FALSE" in str(r.get("audit_verdict", "") or "").upper())
        self.assertEqual(fp_leak, 0, "audit_verdict=FALSE-POSITIVE leaked into pilot_audited")

    def test_backup_file_exists(self):
        self.assertTrue(BACKUP.exists(), f"mandatory backup missing: {BACKUP}")
        rows = list(_iter_jsonl(BACKUP))
        self.assertEqual(len(rows), 1546, "backup should contain pre-quarantine total 1546")

    def test_vault_invariant_library_default_no_tier5(self):
        result = subprocess.run(
            ["python3", str(MCP), "--call", "vault_invariant_library", "--args", '{"limit":2000}'],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, f"MCP call failed: {result.stderr}")
        data = json.loads(result.stdout)
        invs = data.get("invariants", [])
        tier5 = sum(1 for i in invs if "tier-5" in str(i.get("verification_tier", "")).lower())
        self.assertEqual(tier5, 0, "tier-5 leaked into default vault_invariant_library response")
        fp_leak = sum(
            1 for i in invs if "FALSE" in str(i.get("audit_verdict", "") or "").upper()
        )
        self.assertEqual(fp_leak, 0, "FP leaked into default vault_invariant_library response")

    def test_vault_invariant_library_min_tier5_still_blocks_fp_via_quality_filter(self):
        # Even with min_verification_tier=5, _quality_passed drops FALSE-POSITIVE
        # records. This is by design (R37): tier-5 records are NEVER returned by v2+
        # callables regardless of explicit override; only direct file inspection
        # surfaces them.
        result = subprocess.run(
            [
                "python3",
                str(MCP),
                "--call",
                "vault_invariant_library",
                "--args",
                '{"limit":2000,"min_verification_tier":5}',
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, f"MCP call failed: {result.stderr}")
        data = json.loads(result.stdout)
        invs = data.get("invariants", [])
        tier5 = sum(1 for i in invs if "tier-5" in str(i.get("verification_tier", "")).lower())
        self.assertEqual(
            tier5, 0, "tier-5 must remain blocked by _quality_passed even with min_tier=5"
        )

    def test_check_72_references_tier5_quarantine(self):
        self.assertTrue(PRE_SUBMIT.exists(), f"pre-submit-check.sh missing: {PRE_SUBMIT}")
        body = PRE_SUBMIT.read_text(encoding="utf-8")
        self.assertIn("HACKERMAN-RECORD-VERIFICATION-TIER", body)
        self.assertIn("quarantine", body.lower())
        self.assertIn("tier-5", body.lower())

    def test_check_72_helper_tool_exists(self):
        self.assertTrue(HKVT_TOOL.exists(), f"Check #72 helper missing: {HKVT_TOOL}")


if __name__ == "__main__":
    unittest.main()
