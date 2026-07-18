"""Tests for tools/prior-audit-dupe-gate.py.

Covers:
  1. No prior_audits/ dir -> verdict no-prior-audits, gate passes (exit 2).
  2. Draft on a component a prior audit covered, NO originality section -> FAIL.
  3. Same draft WITH an originality section -> PASS (adjacent-review addressed).
  4. Clear draft (no component overlap) -> verdict clear, PASS.
  5. call-decompressor anchor case: draft mentions call-decompressor + DoS
     size-cap; prior audit mentions call-decompressor + DoS -> likely-dupe,
     FAIL without originality section.
  6. likely-dupe WITH originality section -> PASS.
  7. --strict mode: exit code 1 on gate failure.
  8. JSON output: schema field present and correct, gate_pass bool, verdicts.
  9. No staging drafts -> verdict no-staging-drafts, gate passes (exit 0).
  10. Rebuttal marker (<!-- prior-audit-dupe-rebuttal: ... -->) -> PASS
      even on likely-dupe without a named section.
  11. Queue rows are checked for prior-audit duplicates.
  12. Queue parse/filtering edge cases fail closed.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "prior-audit-dupe-gate.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("prior_audit_dupe_gate", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["prior_audit_dupe_gate"] = module
    spec.loader.exec_module(module)
    return module


pad = _load_module()


# ---------------------------------------------------------------------------
# Fixture text helpers
# ---------------------------------------------------------------------------

PRIOR_AUDIT_ISMP_TEXT = """\
Security Review Report - ISMP Baseline Audit v1.0

6.1 Missing access control on dispatch
Risk: Medium
The `dispatch` function in `pallet-ismp` does not restrict callers.
Recommendation: Add an allow-list of authorized dispatchers.

6.10 Call Decompressor size-cap bypass leads to DoS
Risk: Low
The `CallDecompressor` pallet accepts compressed call data without enforcing
a maximum decompressed size. A malicious actor can submit a specially crafted
compressed payload that decompresses to gigabytes, exhausting node memory and
causing a denial-of-service. The team has accepted this risk pending a future
resource-metering update.
Recommendation: Enforce a maximum decompressed size cap (e.g. 2 MB).

6.11 Unchecked arithmetic in fee calculation
Risk: Low
Integer overflow in fee computation in `pallet-hyperbridge`.
"""

DRAFT_CALL_DECOMPRESSOR_NO_ORIG = """\
# Call-decompressor size-cap bypass causes DoS on Hyperbridge nodes

**Severity**: Low
**Component**: `CallDecompressor` pallet, `pallet-ismp`

## Summary

The `CallDecompressor` in the Hyperbridge runtime does not enforce a
maximum decompressed size. An attacker can submit a payload that triggers
denial-of-service via resource exhaustion on nodes.

## Impact

Nodes processing compressed call data exhaust memory, causing a
denial of service (DoS) condition.

## Recommended Fix

Add a `MAX_DECOMPRESSED_SIZE` cap in `call_decompressor.rs`.
"""

DRAFT_CALL_DECOMPRESSOR_WITH_ORIG = DRAFT_CALL_DECOMPRESSOR_NO_ORIG + """
## Duplicate Preflight

Prior audit SRL ISMP-baseline finding 6.10 covers a similar call-decompressor
DoS via missing size cap. L31 Q1: our draft targets `call_decompressor.rs`
in the current audit-pin commit; the SRL finding targeted an earlier version
with a different code path. L31 Q2: the prior finding's recommended fix
(adding a size cap) was risk-accepted by the team and not implemented; our
draft identifies the same unfixed root cause and argues it should be escalated.
Distinct filing is warranted because the risk-accepted status predates the
current audit scope.
"""

DRAFT_CLEAR = """\
# Missing nonce invalidation in governance proposal execution

**Severity**: High
**Component**: `pallet-governance`

## Summary

The governance pallet does not invalidate proposal nonces on execution,
allowing replay attacks on passed proposals.

## Impact

An attacker can replay an already-executed governance proposal.

## Recommended Fix

Track executed proposal hashes in storage.
"""

DRAFT_ADJACENT_PALLET_ISMP_NO_ORIG = """\
# Unauthorized dispatch via pallet-ismp allows state corruption

**Severity**: Medium
**Component**: `pallet-ismp`, `dispatch` function

## Summary

The `dispatch` function on `pallet-ismp` lacks caller restrictions.
An attacker can forge dispatch calls leading to unauthorized state changes.

## Recommended Fix

Add an allow-list of authorized dispatchers.
"""

DRAFT_ADJACENT_WITH_ORIG = DRAFT_ADJACENT_PALLET_ISMP_NO_ORIG + """
## Originality

Prior audit SRL ISMP-baseline finding 6.1 covers missing access control on
`dispatch`. Our finding is distinct: L31 Q1 - we target `FinalizeMessage`
at a different call site (line 88); L31 Q2 - fixing 6.1's allow-list would
NOT fix our unauthorized dispatch via the `FinalizeMessage` entry point
which bypasses the same allow-list via a different code path.
"""

DRAFT_WITH_REBUTTAL_MARKER = """\
# Call-decompressor size-cap bypass causes DoS on Hyperbridge nodes

<!-- prior-audit-dupe-rebuttal: SRL 6.10 was risk-accepted; current audit-pin reintroduced the same uncapped path after refactor at call_decompressor.rs:42; distinct. -->

**Severity**: Low
**Component**: `CallDecompressor` pallet, `pallet-ismp`

## Summary

The `CallDecompressor` in the Hyperbridge runtime does not enforce a
maximum decompressed size causing denial-of-service (DoS).
"""


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _run_tool(*args: str) -> tuple[int, str, str]:
    """Run the gate tool via subprocess and return (returncode, stdout, stderr)."""
    cmd = [sys.executable, str(TOOL_PATH)] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


class TestPriorAuditDupeGate(unittest.TestCase):

    # ------------------------------------------------------------------
    # Test 1: no prior_audits/ dir -> no-prior-audits, exit 2
    # ------------------------------------------------------------------
    def test_01_no_prior_audits_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True)
            (staging / "draft-foo.md").write_text("# Some finding\n\nContent here.\n")

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--json")
            self.assertEqual(rc, 2, msg=f"Expected exit 2 for no-prior-audits; got {rc}")
            data = json.loads(stdout)
            self.assertEqual(data["verdict_summary"], "no-prior-audits")
            self.assertTrue(data["gate_pass"])
            self.assertEqual(data["schema"], "auditooor.prior_audit_dupe_gate.v1")

    # ------------------------------------------------------------------
    # Test 2: adjacent draft, NO originality section -> FAIL (exit 1)
    # ------------------------------------------------------------------
    def test_02_adjacent_no_originality_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True)
            (staging / "draft-adjacent.md").write_text(DRAFT_ADJACENT_PALLET_ISMP_NO_ORIG)

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--json")
            self.assertEqual(rc, 1, msg=f"Expected exit 1 for adjacent-no-orig; got {rc}")
            data = json.loads(stdout)
            self.assertFalse(data["gate_pass"])
            draft = data["drafts"][0]
            self.assertIn(draft["verdict"], ("adjacent-review", "likely-dupe"))
            self.assertFalse(draft["has_originality_section"])

    # ------------------------------------------------------------------
    # Test 3: adjacent draft WITH originality section -> PASS (exit 0)
    # ------------------------------------------------------------------
    def test_03_adjacent_with_originality_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True)
            (staging / "draft-adjacent-orig.md").write_text(DRAFT_ADJACENT_WITH_ORIG)

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--json")
            self.assertEqual(rc, 0, msg=f"Expected exit 0 for adjacent+orig; got {rc}\n{stdout}")
            data = json.loads(stdout)
            self.assertTrue(data["gate_pass"])
            draft = data["drafts"][0]
            self.assertTrue(draft["gate_pass"])
            self.assertTrue(draft["has_originality_section"])

    # ------------------------------------------------------------------
    # Test 4: clear draft (no component overlap) -> clear, PASS
    # ------------------------------------------------------------------
    def test_04_clear_draft_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True)
            (staging / "draft-clear.md").write_text(DRAFT_CLEAR)

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--json")
            self.assertEqual(rc, 0, msg=f"Expected exit 0 for clear draft; got {rc}")
            data = json.loads(stdout)
            self.assertTrue(data["gate_pass"])
            draft = data["drafts"][0]
            self.assertEqual(draft["verdict"], "clear")

    # ------------------------------------------------------------------
    # Test 5: call-decompressor anchor case -> likely-dupe, FAIL
    # ------------------------------------------------------------------
    def test_05_call_decompressor_likely_dupe_fails(self):
        """The canonical 2026-05-22 anchor: call-decompressor + DoS."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True)
            (staging / "draft-call-decompressor.md").write_text(DRAFT_CALL_DECOMPRESSOR_NO_ORIG)

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--json")
            self.assertEqual(rc, 1, msg=f"Expected exit 1 for likely-dupe; got {rc}\n{stdout}")
            data = json.loads(stdout)
            self.assertFalse(data["gate_pass"])
            draft = data["drafts"][0]
            # Must be likely-dupe (component AND impact overlap)
            self.assertEqual(draft["verdict"], "likely-dupe",
                             msg=f"Expected likely-dupe; got {draft['verdict']}")
            # Shared tokens must include call-decompressor-related terms
            all_shared = []
            for adj in draft["adjacencies"]:
                all_shared.extend(adj["shared_component_tokens"])
            # At least one of the decompressor or ismp tokens must appear
            self.assertTrue(
                any("decompressor" in t or "ismp" in t or "calldecompressor" in t
                    for t in all_shared),
                msg=f"Expected decompressor/ismp in shared tokens; got {all_shared}"
            )
            # Impact class must include dos
            all_impacts = []
            for adj in draft["adjacencies"]:
                all_impacts.extend(adj["shared_impact_classes"])
            self.assertIn("dos", all_impacts,
                          msg=f"Expected 'dos' in shared impacts; got {all_impacts}")

    # ------------------------------------------------------------------
    # Test 6: likely-dupe WITH originality section -> PASS
    # ------------------------------------------------------------------
    def test_06_likely_dupe_with_originality_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True)
            (staging / "draft-call-decompressor-orig.md").write_text(
                DRAFT_CALL_DECOMPRESSOR_WITH_ORIG
            )

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--json")
            self.assertEqual(rc, 0, msg=f"Expected exit 0 for likely-dupe+orig; got {rc}\n{stdout}")
            data = json.loads(stdout)
            self.assertTrue(data["gate_pass"])
            draft = data["drafts"][0]
            self.assertTrue(draft["gate_pass"])
            self.assertTrue(draft["has_originality_section"])

    # ------------------------------------------------------------------
    # Test 7: --strict mode exit code
    # ------------------------------------------------------------------
    def test_07_strict_mode_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True)
            (staging / "draft-call-decompressor.md").write_text(DRAFT_CALL_DECOMPRESSOR_NO_ORIG)

            rc_strict, _, _ = _run_tool(
                "--workspace", str(ws), "--strict", "--json"
            )
            self.assertEqual(rc_strict, 1, msg=f"--strict should exit 1; got {rc_strict}")

    # ------------------------------------------------------------------
    # Test 8: JSON schema fields are present
    # ------------------------------------------------------------------
    def test_08_json_schema_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True)
            (staging / "draft-clear.md").write_text(DRAFT_CLEAR)

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--json")
            data = json.loads(stdout)

            required_top = [
                "schema", "workspace", "verdict_summary", "gate_pass",
                "prior_audit_count", "draft_count", "verdict_counts",
                "failures", "drafts",
            ]
            for field in required_top:
                self.assertIn(field, data, msg=f"Missing top-level field: {field}")
            self.assertEqual(data["schema"], "auditooor.prior_audit_dupe_gate.v1")
            self.assertIsInstance(data["gate_pass"], bool)
            self.assertIsInstance(data["drafts"], list)
            self.assertEqual(len(data["drafts"]), 1)

            draft = data["drafts"][0]
            required_draft = [
                "draft", "draft_name", "verdict", "gate_pass", "reason",
                "has_originality_section", "has_rebuttal_marker",
                "adjacencies", "draft_component_tokens_count",
                "draft_impact_classes",
            ]
            for field in required_draft:
                self.assertIn(field, draft, msg=f"Missing draft-level field: {field}")

    # ------------------------------------------------------------------
    # Test 9: no staging drafts -> no-staging-drafts, exit 0
    # ------------------------------------------------------------------
    def test_09_no_staging_drafts(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            # Do NOT create submissions/staging/

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--json")
            self.assertEqual(rc, 0, msg=f"Expected exit 0 for no staging; got {rc}")
            data = json.loads(stdout)
            self.assertEqual(data["verdict_summary"], "no-staging-drafts")
            self.assertTrue(data["gate_pass"])

    # ------------------------------------------------------------------
    # Test 10: rebuttal marker bypasses section requirement
    # ------------------------------------------------------------------
    def test_10_rebuttal_marker_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            staging = ws / "submissions" / "staging"
            staging.mkdir(parents=True)
            (staging / "draft-rebuttal.md").write_text(DRAFT_WITH_REBUTTAL_MARKER)

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--json")
            self.assertEqual(rc, 0, msg=f"Expected exit 0 for rebuttal-marker draft; got {rc}\n{stdout}")
            data = json.loads(stdout)
            self.assertTrue(data["gate_pass"])
            draft = data["drafts"][0]
            self.assertTrue(draft["gate_pass"])
            self.assertTrue(draft["has_rebuttal_marker"])

    def test_11_queue_likely_dupe_without_originality_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            queue = ws / ".auditooor" / "exploit_queue.source_mined.json"
            queue.parent.mkdir()
            queue.write_text(json.dumps({
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-DUPE",
                        "title": "CallDecompressor size-cap bypass causes DoS",
                        "component": "`CallDecompressor` pallet, `pallet-ismp`",
                        "selected_impact": "denial-of-service via resource exhaustion",
                        "source_refs": ["call_decompressor.rs:42"],
                    }
                ],
            }))

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--queue", str(queue), "--json")

            self.assertEqual(rc, 1, stdout)
            data = json.loads(stdout)
            self.assertEqual(data["mode"], "queue")
            self.assertEqual(data["row_count"], 1)
            self.assertFalse(data["gate_pass"])
            row = data["drafts"][0]
            self.assertEqual(row["lead_id"], "EQ-DUPE")
            self.assertEqual(row["verdict"], "likely-dupe")
            self.assertFalse(row["gate_pass"])

    def test_12_queue_likely_dupe_with_originality_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            queue = ws / ".auditooor" / "exploit_queue.source_mined.json"
            queue.parent.mkdir()
            queue.write_text(json.dumps({
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-DUPE",
                        "title": "CallDecompressor size-cap bypass causes DoS",
                        "component": "`CallDecompressor` pallet, `pallet-ismp`",
                        "selected_impact": "denial-of-service via resource exhaustion",
                        "source_refs": ["call_decompressor.rs:42"],
                        "originality": (
                            "Prior SRL 6.10 is acknowledged; this row targets a "
                            "different current audit-pin path and needs reviewer judgment."
                        ),
                    }
                ],
            }))

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--queue", str(queue), "--json")

            self.assertEqual(rc, 0, stdout)
            data = json.loads(stdout)
            self.assertTrue(data["gate_pass"])
            self.assertTrue(data["drafts"][0]["has_originality_section"])

    def test_13_queue_no_prior_audits_returns_advisory_rc_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            queue = ws / ".auditooor" / "exploit_queue.source_mined.json"
            queue.parent.mkdir()
            queue.write_text(json.dumps({
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [{"lead_id": "EQ-001", "title": "source-mined candidate"}],
            }))

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--queue", str(queue), "--json")

            self.assertEqual(rc, 2)
            data = json.loads(stdout)
            self.assertEqual(data["mode"], "queue")
            self.assertEqual(data["verdict_summary"], "no-prior-audits")
            self.assertTrue(data["gate_pass"])

    def test_14_malformed_queue_json_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            queue = ws / ".auditooor" / "exploit_queue.source_mined.json"
            queue.parent.mkdir()
            queue.write_text('{"schema": "auditooor.exploit_queue.source_mined.v1", "queue": [')

            rc, stdout, stderr = _run_tool("--workspace", str(ws), "--queue", str(queue), "--json")

            self.assertEqual(rc, 3)
            self.assertEqual(stdout, "")
            self.assertIn("ERROR: malformed queue JSON", stderr)

    def test_15_queue_terminal_filtering_uses_exact_normalized_states(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "srl_ismp_baseline.txt").write_text(PRIOR_AUDIT_ISMP_TEXT)
            queue = ws / ".auditooor" / "exploit_queue.source_mined.json"
            queue.parent.mkdir()
            queue.write_text(json.dumps({
                "schema": "auditooor.exploit_queue.source_mined.v1",
                "queue": [
                    {
                        "lead_id": "EQ-TERMINAL-ADVISORY",
                        "status": "advisory",
                        "title": "CallDecompressor size-cap bypass causes DoS",
                        "component": "`CallDecompressor` pallet, `pallet-ismp`",
                        "selected_impact": "denial-of-service via resource exhaustion",
                    },
                    {
                        "lead_id": "EQ-NEEDS-ADVISORY-REVIEW",
                        "status": "needs_advisory_review",
                        "title": "CallDecompressor size-cap bypass causes DoS",
                        "component": "`CallDecompressor` pallet, `pallet-ismp`",
                        "selected_impact": "denial-of-service via resource exhaustion",
                    },
                    {
                        "lead_id": "EQ-NOT-DUPLICATE-CHECKED",
                        "verdict": "not_duplicate_checked",
                        "title": "CallDecompressor size-cap bypass causes DoS",
                        "component": "`CallDecompressor` pallet, `pallet-ismp`",
                        "selected_impact": "denial-of-service via resource exhaustion",
                    },
                ],
            }))

            rc, stdout, _ = _run_tool("--workspace", str(ws), "--queue", str(queue), "--json")

            self.assertEqual(rc, 1, stdout)
            data = json.loads(stdout)
            self.assertEqual(data["row_count"], 2)
            lead_ids = {row["lead_id"] for row in data["drafts"]}
            self.assertEqual(
                lead_ids,
                {"EQ-NEEDS-ADVISORY-REVIEW", "EQ-NOT-DUPLICATE-CHECKED"},
            )
            self.assertFalse(data["gate_pass"])


if __name__ == "__main__":
    unittest.main()
