#!/usr/bin/env python3
"""V5 CAMPAIGN PR 3 — tests for tools/source-mining-campaign.py.

Hermetic, stdlib-only. Each test scaffolds a temp workspace and a temp
output dir, and injects a mock dispatcher so no LLM call is ever made.
The `tools/llm-dispatch.py` shell-out path is exercised only via the
``--help`` and ``--dry-run`` smoke checks (subprocess, but no network).

Codex's exact acceptance list (each maps to a test):

  1. Mock provider outputs with one valid candidate, one OOS candidate,
     one impossible trigger.
  2. OOS / impossible candidates rejected.
  3. `source_coverage.json` reports files skipped + why.
  4. No "likely new", "High", "Critical", "safe to submit" verdict can
     be emitted by Kimi alone (test the prompt template's restriction
     language).
  5. Resume mid-campaign works.

Plus defensive cases for the promotion gate, JSONL parsing, and the
domain-slicer fallback.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "source-mining-campaign.py"


def _import_tool():
    spec = importlib.util.spec_from_file_location("source_mining_campaign", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SMC = _import_tool()


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

ORACLE_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Oracle {
    function getPrice() external view returns (uint256) {
        return 1e18;
    }
}
"""

VAULT_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    function deposit(uint256 a) external {}
}
"""

# Dispatcher response shapes — these emulate the JSONL output an LLM
# would produce in response to our packet.

KIMI_GOOD_OUTPUT = (
    json.dumps({
        "candidate_id": "oracle-stale-001",
        "source_files": ["src/Oracle.sol:3-7"],
        "bug_shape": "stale price returned without timestamp check",
        "reachable_non_privileged_path": "anyone can call getPrice",
        "required_state": "feed has not updated for >1 hour",
        "impact_hypothesis": "downstream borrows priced on stale data",
        "scope_risk": "in-scope per SCOPE.md",
        "oos_risk": "none",
        "prior_art_risk": "common pattern; check library",
        "exact_checks_needed_next": "grep stalencheck patterns",
    })
    + "\n"
    + json.dumps({
        "candidate_id": "oos-admin-002",
        "source_files": ["src/Oracle.sol:1"],
        "bug_shape": "admin can set price arbitrarily",
        "reachable_non_privileged_path": "n/a",
        "required_state": "leaked private key for owner",
        "impact_hypothesis": "owner can rug",
        "scope_risk": "centralization risk acknowledged",
        "oos_risk": "out-of-scope per project README",
        "prior_art_risk": "n/a",
        "exact_checks_needed_next": "n/a",
    })
    + "\n"
    + json.dumps({
        "candidate_id": "impossible-003",
        "source_files": ["src/Vault.sol:3"],
        "bug_shape": "if ecrecover is broken, signatures forged",
        "reachable_non_privileged_path": "anyone",
        "required_state": "break sha-256 collision resistance",
        "impact_hypothesis": "signatures forged",
        "scope_risk": "in-scope",
        "oos_risk": "no",
        "prior_art_risk": "n/a",
        "exact_checks_needed_next": "n/a",
    })
    + "\n"
)

KIMI_NO_LINE_CITE = json.dumps({
    "candidate_id": "no-cite-004",
    "source_files": ["src/Vault.sol"],  # no :LINE
    "bug_shape": "deposit accepts zero amount silently",
    "reachable_non_privileged_path": "anyone",
    "required_state": "deposit(0)",
    "impact_hypothesis": "no-op event noise",
    "scope_risk": "in",
    "oos_risk": "no",
    "prior_art_risk": "n/a",
    "exact_checks_needed_next": "trace event logs",
}) + "\n"


def _build_minimax_response(kimi_text: str, *, force_keep: bool = False) -> str:
    """Produce a Minimax-shaped response keyed off the kimi candidate IDs."""
    out_lines: list[str] = []
    for line in kimi_text.strip().splitlines():
        try:
            cand = json.loads(line)
        except ValueError:
            continue
        cid = cand.get("candidate_id")
        if force_keep:
            verdict = "KEEP_FOR_LOCAL_VERIFICATION"
            reason = "test-force-keep"
        elif cid == "oos-admin-002":
            verdict = "REJECT_OOS"
            reason = "out-of-scope: admin compromise"
        elif cid == "impossible-003":
            verdict = "REJECT_INSUFFICIENT_IMPACT"
            reason = "impossible trigger"
        elif cid == "no-cite-004":
            verdict = "KEEP_FOR_LOCAL_VERIFICATION"
            reason = "kimi gate should drop pre-minimax"
        else:
            verdict = "KEEP_FOR_LOCAL_VERIFICATION"
            reason = "needs local PoC"
        out_lines.append(json.dumps({
            "candidate_id": cid,
            "classification": verdict,
            "reason": reason,
            "next_check": "verify line cite",
        }))
    return "\n".join(out_lines) + "\n"


def _scaffold_ws(tmp: Path) -> Path:
    (tmp / "src").mkdir(parents=True, exist_ok=True)
    (tmp / "src" / "Oracle.sol").write_text(ORACLE_SOL, encoding="utf-8")
    (tmp / "src" / "Vault.sol").write_text(VAULT_SOL, encoding="utf-8")
    (tmp / "SCOPE.md").write_text(
        "# In Scope\n- src/Oracle.sol\n- src/Vault.sol\n", encoding="utf-8"
    )
    return tmp


def _make_runner(kimi_text: str, minimax_text: str):
    """Build a mock dispatcher that returns canned responses keyed by provider."""
    calls: list[dict] = []

    def runner(provider, prompt_text, *, audit_dir, timeout, max_tokens, input_is_truncated):
        calls.append({
            "provider": provider,
            "prompt_len": len(prompt_text),
            "input_is_truncated": input_is_truncated,
        })
        if provider == "kimi":
            return 0, kimi_text, ""
        if provider == "minimax":
            return 0, minimax_text, ""
        return 3, "", "unknown-provider"

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


# ---------------------------------------------------------------------------
# Provider preflight packet shape
# ---------------------------------------------------------------------------

class ProviderPreflightPacketTests(unittest.TestCase):
    def test_kimi_packet_contains_source_extract_template_fields(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            packet, coverage = SMC.build_kimi_packet(
                workspace=ws,
                domain="oracle",
                files=["src/Oracle.sol"],
                truth_block="scope truth",
                char_cap=100_000,
            )

        self.assertIn("workspace_path:", packet)
        self.assertIn("memory_context:", packet)
        self.assertIn("target_files:", packet)
        self.assertIn("hypotheses:", packet)
        self.assertIn("prior_failed_attempts:", packet)
        self.assertIn("expected_output_shape:", packet)
        self.assertIn("src/Oracle.sol", packet)
        self.assertEqual(coverage["files_included"], ["src/Oracle.sol"])

    def test_kimi_packet_carries_impact_worklist_context_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            context = {
                "status": "present",
                "artifact": str(ws / ".auditooor" / "impact_family_worklists.json"),
                "worklist_count": 1,
                "worklists": [
                    {
                        "impact_id": "critical-001-direct-theft",
                        "impact_family": "asset_custody",
                        "proof_class": "executed_with_manifest",
                        "required_artifacts": ["impact_contract", "poc_execution_manifest"],
                        "relevant_source_roots": ["src"],
                        "components": [
                            {"component_id": "Vault.withdraw", "file": "src/Vault.sol", "line": 12}
                        ],
                        "oos_traps": ["exclude admin-key compromise"],
                    }
                ],
            }
            packet, coverage = SMC.build_kimi_packet(
                workspace=ws,
                domain="vault-share-math",
                files=["src/Oracle.sol"],
                truth_block="scope truth",
                impact_worklist_context=context,
                char_cap=100_000,
            )

        self.assertIn("LISTED IMPACT WORKLIST CONTEXT", packet)
        self.assertIn("NOT_SUBMIT_READY", packet)
        self.assertIn("critical-001-direct-theft", packet)
        self.assertIn("Vault.withdraw", packet)
        self.assertEqual(coverage["impact_worklist_context"]["worklist_count"], 1)
        self.assertFalse(coverage["impact_worklist_context"]["submit_ready"])

    def test_minimax_packet_contains_adversarial_kill_template_fields(self):
        packet, truncated = SMC.build_minimax_packet(
            workspace=Path("/tmp/ws"),
            domain="oracle",
            truth_block="scope truth",
            kimi_candidates=[{"candidate_id": "oracle-stale-001"}],
            char_cap=100_000,
        )

        self.assertFalse(truncated)
        self.assertIn("workspace_path:", packet)
        self.assertIn("memory_context:", packet)
        self.assertIn("candidate_list:", packet)
        self.assertIn("oos_text:", packet)
        self.assertIn("truncation_flag: complete", packet)
        self.assertIn("expected_output_shape:", packet)
        self.assertIn("oracle-stale-001", packet)


# ---------------------------------------------------------------------------
# 1. Promotion gate / OOS / impossible trigger rejection
# ---------------------------------------------------------------------------

class PromotionGateTests(unittest.TestCase):
    """Tests 1, 2: valid + OOS + impossible candidates → exactly one survivor."""

    def test_oos_and_impossible_rejected_keep_one_survivor(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            runner = _make_runner(KIMI_GOOD_OUTPUT, _build_minimax_response(KIMI_GOOD_OUTPUT))
            manifest = SMC.run_campaign(
                workspace=ws,
                out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000,
                timeout=10.0,
                max_tokens=4000,
                runner=runner,
            )
            survivors = json.loads((out / "survivors.json").read_text(encoding="utf-8"))
            rejected = json.loads((out / "rejected.json").read_text(encoding="utf-8"))
            survivor_ids = [s["candidate_id"] for s in survivors]
            rejected_ids = [r["candidate_id"] for r in rejected]
            self.assertEqual(survivor_ids, ["oracle-stale-001"])
            self.assertEqual(survivors[0]["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(survivors[0]["selected_impact"], "")
            self.assertEqual(survivors[0]["severity"], "none")
            self.assertTrue(survivors[0]["impact_contract_required"])
            self.assertIn("oos-admin-002", rejected_ids)
            self.assertIn("impossible-003", rejected_ids)
            # Rejection reasons are explicit.
            reasons_by_id = {r["candidate_id"]: r["rejection_reason"] for r in rejected}
            self.assertTrue(reasons_by_id["oos-admin-002"].startswith("oos-marker:"))
            self.assertTrue(
                reasons_by_id["impossible-003"].startswith("impossible-trigger:")
            )
            routing_manifest = json.loads(
                (out / "outcome_calibrated_routing.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                routing_manifest["overall_routing_status"],
                "input_only_local_verification_required",
            )
            self.assertFalse(routing_manifest["llm_corpus_mining_is_proof"])
            provider_tasks = {
                (row["provider"], row["task_type"])
                for row in routing_manifest["provider_rows"]
            }
            self.assertIn(("kimi", "source-extraction"), provider_tasks)
            self.assertIn(("minimax", "adversarial-kill"), provider_tasks)
            self.assertIn(("minimax", "contradiction-search"), provider_tasks)
            m14_rows = [
                row for row in routing_manifest["provider_rows"]
                if row["task_type"] == "contradiction-search"
            ]
            self.assertEqual(len(m14_rows), 1)
            self.assertTrue(m14_rows[0]["m14_trap_required"])
            summary = (out / "summary.md").read_text(encoding="utf-8")
            self.assertIn("allocation_status: blocked_missing_impact_contract", summary)

    def test_needs_more_source_does_not_promote(self):
        """Per Codex's promotion gate step (b), only KEEP_FOR_LOCAL_VERIFICATION
        promotes. NEEDS_MORE_SOURCE must route to rejected (Minimax pre-review
        attack #6 — silent-promote)."""
        kimi = json.dumps({
            "candidate_id": "needs-more-005",
            "source_files": ["src/Oracle.sol:1-2"],
            "bug_shape": "edge case",
            "reachable_non_privileged_path": "anyone",
            "required_state": "n/a",
            "impact_hypothesis": "h",
            "scope_risk": "in",
            "oos_risk": "no",
            "prior_art_risk": "n/a",
            "exact_checks_needed_next": "more source",
        }) + "\n"
        minimax = json.dumps({
            "candidate_id": "needs-more-005",
            "classification": "NEEDS_MORE_SOURCE",
            "reason": "truncated input",
            "next_check": "expand packet",
        }) + "\n"
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=_make_runner(kimi, minimax),
            )
            survivors = json.loads((out / "survivors.json").read_text(encoding="utf-8"))
            rejected = json.loads((out / "rejected.json").read_text(encoding="utf-8"))
            self.assertEqual(survivors, [])
            self.assertEqual(len(rejected), 1)
            self.assertEqual(rejected[0]["rejection_reason"], "minimax:NEEDS_MORE_SOURCE")

    def test_missing_line_cite_rejected_even_when_minimax_keeps(self):
        kimi = KIMI_NO_LINE_CITE
        # Minimax votes KEEP — gate must still reject for missing line cite.
        minimax = json.dumps({
            "candidate_id": "no-cite-004",
            "classification": "KEEP_FOR_LOCAL_VERIFICATION",
            "reason": "force-keep",
            "next_check": "n/a",
        }) + "\n"
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws,
                out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000,
                timeout=10.0,
                max_tokens=4000,
                runner=_make_runner(kimi, minimax),
            )
            survivors = json.loads((out / "survivors.json").read_text(encoding="utf-8"))
            rejected = json.loads((out / "rejected.json").read_text(encoding="utf-8"))
            self.assertEqual(survivors, [])
            self.assertEqual(rejected[0]["rejection_reason"], "missing-line-cite")

    def test_kimi_only_line_cited_candidates_are_pending_not_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws,
                out_dir=out,
                providers=("kimi",),
                packet_budget=100_000,
                timeout=10.0,
                max_tokens=4000,
                runner=_make_runner(KIMI_GOOD_OUTPUT, ""),
            )
            survivors = json.loads((out / "survivors.json").read_text(encoding="utf-8"))
            rejected = json.loads((out / "rejected.json").read_text(encoding="utf-8"))
            pending = json.loads(
                (out / "survivors_pending_minimax_review.json").read_text(encoding="utf-8")
            )
            self.assertEqual(survivors, [])
            self.assertEqual(manifest["pending_review_count"], 1)
            self.assertEqual([p["candidate_id"] for p in pending], ["oracle-stale-001"])
            self.assertEqual(pending[0]["pending_reason"], "pending-minimax-review")
            self.assertNotIn(
                "oracle-stale-001",
                [r.get("candidate_id") for r in rejected],
            )
            summary = (out / "summary.md").read_text(encoding="utf-8")
            self.assertIn("pending_review: 1", summary)
            self.assertIn("Pending Provider Review", summary)


# ---------------------------------------------------------------------------
# 3. Source coverage report
# ---------------------------------------------------------------------------

class SourceCoverageTests(unittest.TestCase):
    """source_coverage.json reports files skipped + why."""

    def test_source_coverage_json_records_included_and_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            # Create a file that will exceed the char-budget so it gets
            # skipped with reason char-budget-exceeded.
            (ws / "src" / "Big.sol").write_text("X" * 1000, encoding="utf-8")
            out = Path(td) / "out"
            runner = _make_runner(KIMI_GOOD_OUTPUT, _build_minimax_response(KIMI_GOOD_OUTPUT))
            SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=500,  # tiny so something gets skipped
                timeout=10.0, max_tokens=4000,
                runner=runner,
            )
            cov = json.loads((out / "source_coverage.json").read_text(encoding="utf-8"))
            self.assertIn("domains", cov)
            # At least one domain reports skips with reasons.
            saw_skip = False
            for dom_name, dom in cov["domains"].items():
                for skip in dom.get("files_skipped", []):
                    self.assertIn("file", skip)
                    self.assertIn("reason", skip)
                    saw_skip = True
            self.assertTrue(saw_skip, "expected at least one skipped file with reason")


# ---------------------------------------------------------------------------
# 4. Prompt-template restriction language
# ---------------------------------------------------------------------------

class PromptRestrictionTests(unittest.TestCase):
    """Kimi cannot emit 'likely new' / 'High' / 'Critical' / 'safe to submit'."""

    def test_kimi_packet_contains_restriction_block(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            packet, _cov = SMC.build_kimi_packet(
                workspace=ws,
                domain="oracle-pricing",
                files=["src/Oracle.sol"],
                truth_block="[truth]",
            )
            for forbidden in ("likely new", "High", "Critical", "safe to submit"):
                self.assertIn(
                    forbidden, packet,
                    f"restriction block must mention forbidden phrase '{forbidden}'",
                )
            # The block should explicitly forbid use, not encourage it.
            self.assertIn("Do NOT use the words", packet)
            self.assertIn("Do NOT propose severities", packet)

    def test_minimax_packet_contains_restriction_block(self):
        packet, truncated = SMC.build_minimax_packet(
            workspace=Path("/tmp/ws-stub"),
            domain="oracle-pricing",
            truth_block="[truth]",
            kimi_candidates=[{"candidate_id": "x"}],
        )
        for forbidden in ("likely new", "High", "Critical", "safe to submit"):
            self.assertIn(forbidden, packet)
        self.assertFalse(truncated)


# ---------------------------------------------------------------------------
# 5. Resume support
# ---------------------------------------------------------------------------

class ResumeTests(unittest.TestCase):
    """Re-running on the same out_dir skips already-dispatched packets."""

    def test_resume_skips_completed_packets(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            runner1 = _make_runner(KIMI_GOOD_OUTPUT, _build_minimax_response(KIMI_GOOD_OUTPUT))
            SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=runner1,
            )
            first_call_count = len(runner1.calls)  # type: ignore[attr-defined]
            self.assertGreater(first_call_count, 0)

            # Second run on the same out_dir.
            runner2 = _make_runner("", "")  # empty — should NOT be called for completed packets
            SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=runner2,
            )
            second_call_count = len(runner2.calls)  # type: ignore[attr-defined]
            self.assertEqual(
                second_call_count, 0,
                "second run should resume from packet markers, not re-dispatch",
            )

            # Survivors and rejected files still present after resume.
            self.assertTrue((out / "survivors.json").is_file())
            self.assertTrue((out / "rejected.json").is_file())

            # Resume must rebuild `all_kimi`/`all_minimax` from per-domain
            # markers — otherwise the promotion gate rejects every
            # candidate as "no-minimax-challenge-for-candidate" and the
            # second-run survivors.json silently empties out. (Closes
            # Kimi pre-review concern #5.)
            survivors_first = json.loads(
                (out / "survivors.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                [s["candidate_id"] for s in survivors_first],
                ["oracle-stale-001"],
                "first run should keep one survivor",
            )

            # Run a third time and confirm the survivor list is still
            # exactly one — proves resume doesn't drop survivors.
            runner3 = _make_runner("", "")
            SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=runner3,
            )
            survivors_third = json.loads(
                (out / "survivors.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                [s["candidate_id"] for s in survivors_third],
                ["oracle-stale-001"],
                "third run should reproduce the same survivor via marker rebuild",
            )


# ---------------------------------------------------------------------------
# Defensive: JSONL parser
# ---------------------------------------------------------------------------

class JsonlParseTests(unittest.TestCase):

    def test_handles_fenced_block(self):
        text = "Here is the output:\n```json\n" + json.dumps({"a": 1}) + "\n" + json.dumps({"b": 2}) + "\n```\n"
        out = SMC.parse_jsonl(text)
        self.assertEqual(out, [{"a": 1}, {"b": 2}])

    def test_handles_array_form(self):
        text = json.dumps([{"a": 1}, {"b": 2}])
        out = SMC.parse_jsonl(text)
        self.assertEqual(out, [{"a": 1}, {"b": 2}])

    def test_drops_invalid_lines(self):
        text = "garbage\n" + json.dumps({"ok": True}) + "\n}}}}\n"
        out = SMC.parse_jsonl(text)
        self.assertEqual(out, [{"ok": True}])


# ---------------------------------------------------------------------------
# Defensive: domain slicer fallback
# ---------------------------------------------------------------------------

class DomainSlicerTests(unittest.TestCase):

    def test_heuristic_groups_oracle_and_vault(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            domains = SMC._slice_domains_heuristic(ws)
            self.assertIn("oracle-pricing", domains)
            self.assertIn("vault-share-math", domains)

    def test_skips_lib_test_mock_paths(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "lib").mkdir()
            (ws / "test").mkdir()
            (ws / "src" / "Oracle.sol").write_text(ORACLE_SOL, encoding="utf-8")
            (ws / "lib" / "VendorOracle.sol").write_text(ORACLE_SOL, encoding="utf-8")
            (ws / "test" / "OracleTest.sol").write_text(ORACLE_SOL, encoding="utf-8")
            domains = SMC._slice_domains_heuristic(ws)
            files = [f for files_ in domains.values() for f in files_]
            self.assertIn("src/Oracle.sol", files)
            self.assertNotIn("lib/VendorOracle.sol", files)
            self.assertNotIn("test/OracleTest.sol", files)


# ---------------------------------------------------------------------------
# Defensive: dispatcher failure mode
# ---------------------------------------------------------------------------

class DispatchFailureTests(unittest.TestCase):
    """When Kimi dispatch fails, the campaign should still emit clean
    artifacts (empty kimi_candidates, empty survivors)."""

    def test_kimi_failure_yields_empty_survivors(self):
        def failing_runner(provider, prompt_text, *, audit_dir, timeout, max_tokens, input_is_truncated):
            return 3, "", "simulated-failure"

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=failing_runner,
            )
            survivors = json.loads((out / "survivors.json").read_text(encoding="utf-8"))
            self.assertEqual(survivors, [])
            self.assertEqual(manifest["survivor_count"], 0)

    def test_all_no_consent_dispatches_fail_loud(self):
        def no_consent_runner(provider, prompt_text, *, audit_dir, timeout, max_tokens, input_is_truncated):
            return 2, "", '{"reason":"cannot-run: no-consent"}'

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=no_consent_runner,
            )
            self.assertEqual(manifest["outcome"], "cannot-run: no-network-consent")
            self.assertGreater(manifest["no_network_consent_count"], 0)
            self.assertEqual(manifest["no_network_consent_count"], manifest["dispatch_attempt_count"])
            self.assertEqual(manifest["survivor_count"], 0)

    def test_mixed_no_consent_dispatches_warn_but_complete(self):
        calls = {"kimi": 0}

        def mixed_runner(provider, prompt_text, *, audit_dir, timeout, max_tokens, input_is_truncated):
            if provider == "kimi":
                calls["kimi"] += 1
                if calls["kimi"] == 1:
                    return 2, "", '{"reason":"cannot-run: no-consent"}'
                return 0, KIMI_GOOD_OUTPUT, ""
            return 0, _build_minimax_response(KIMI_GOOD_OUTPUT), ""

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=mixed_runner,
            )
            self.assertNotEqual(manifest.get("outcome"), "cannot-run: no-network-consent")
            self.assertGreater(manifest["no_network_consent_count"], 0)
            self.assertGreaterEqual(manifest["consent_skipped_domains"], 1)


# ---------------------------------------------------------------------------
# Defensive: Minimax truncation flag fires when packet > threshold
# ---------------------------------------------------------------------------

class MinimaxTruncationTests(unittest.TestCase):

    def test_input_is_truncated_when_packet_exceeds_threshold(self):
        seen_flags: list[bool] = []

        def runner(provider, prompt_text, *, audit_dir, timeout, max_tokens, input_is_truncated):
            if provider == "minimax":
                seen_flags.append(input_is_truncated)
                return 0, "", ""
            # Kimi returns many candidates so the Minimax packet grows.
            big_candidates: list[str] = []
            for i in range(50):
                big_candidates.append(json.dumps({
                    "candidate_id": f"c-{i}",
                    "source_files": [f"src/Oracle.sol:{i}-{i+1}"],
                    "bug_shape": "x" * 2000,
                    "reachable_non_privileged_path": "anyone",
                    "required_state": "n/a",
                    "impact_hypothesis": "h",
                    "scope_risk": "in",
                    "oos_risk": "no",
                    "prior_art_risk": "no",
                    "exact_checks_needed_next": "n/a",
                }))
            return 0, "\n".join(big_candidates) + "\n", ""

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=runner,
            )
            self.assertTrue(any(seen_flags), "minimax should have been called")
            self.assertTrue(
                all(seen_flags),
                "minimax should be flagged --input-is-truncated when packet > 70K chars",
            )


# ---------------------------------------------------------------------------
# Smoke: --help and --dry-run via subprocess
# ---------------------------------------------------------------------------

class CliSmokeTests(unittest.TestCase):

    def test_help_works(self):
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("source-mining-campaign", proc.stdout)
        self.assertIn("--providers", proc.stdout)

    def test_dry_run_writes_source_coverage(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            proc = subprocess.run(
                [
                    sys.executable, str(TOOL),
                    "--workspace", str(ws),
                    "--out", str(out),
                    "--dry-run",
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue((out / "source_coverage.json").is_file())
            cov = json.loads((out / "source_coverage.json").read_text(encoding="utf-8"))
            self.assertTrue(cov.get("dry_run"))

    def test_dry_run_works_outside_repo_cwd(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--out",
                    str(out),
                    "--dry-run",
                ],
                cwd=td,
                env={**os.environ, "PYTHONPATH": ""},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            cov = json.loads((out / "source_coverage.json").read_text(encoding="utf-8"))
            self.assertTrue(cov.get("dry_run"))

    def test_invalid_workspace_exits_2(self):
        proc = subprocess.run(
            [
                sys.executable, str(TOOL),
                "--workspace", "/nonexistent-/-no-way-this-exists-12345",
                "--out", "/tmp/out_smc_test_invalid",
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)


# ---------------------------------------------------------------------------
# Typed deep_candidate.v1 emission (PR #291 schema integration restore)
# ---------------------------------------------------------------------------

class TypedCandidateEmissionTests(unittest.TestCase):
    """Verify that survivors of the 4-step gate are also emitted as typed
    `deep_candidate.v1` records under `<workspace>/deep_candidates/`.

    The integration was lost during the parallel-merge of PR #291 +
    PR #296 (rebase took #296's full wrapper, deferred the typed
    emission). These tests pin the restored behaviour."""

    def _validate_deep_candidate_doc(self, doc: dict) -> None:
        """Lightweight schema check: required top-level keys per
        ``docs/schemas/deep_candidate.v1.json``. Full JSON-Schema
        validation lives in ``test_deep_candidate_schema.py``; here
        we just assert the wrapper produced something the validator
        will accept."""
        for key in (
            "schema_version",
            "candidate_id",
            "lane",
            "files",
            "claim",
            "trigger",
            "impact",
            "reproduction",
            "confidence",
            "promotion_status",
            "blocking_questions",
        ):
            self.assertIn(key, doc, f"missing required key: {key}")
        self.assertEqual(doc["lane"], "source_mine")
        self.assertEqual(doc["confidence"], "low")
        self.assertEqual(doc["promotion_status"], "investigate")
        self.assertGreaterEqual(len(doc["blocking_questions"]), 1)

    def test_emit_typed_candidates_writes_one_doc_per_survivor(self):
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            survivors = [
                {
                    "candidate_id": "src/Vault.sol-claim-0",
                    "bug_shape": "missing-bounds-check-in-deposit",
                    "files": ["src/Vault.sol"],
                    "description": "Deposit accepts negative shares.",
                    "trigger": "call deposit(-1)",
                    "impact": "Net steal-from-vault path.",
                    "claude_poc_task": "Reproduce in Foundry test.",
                },
                {
                    "candidate_id": "src/Bridge.sol-claim-0",
                    "bug_shape": "stale-nonce-replay",
                    "files": ["src/Bridge.sol"],
                    "description": "Replay window unbounded.",
                },
            ]
            count, paths = mod.emit_typed_candidates(ws, survivors)
            self.assertEqual(count, 2)
            self.assertEqual(len(paths), 2)
            for path in paths:
                self.assertTrue(path.is_file())
                doc = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(doc["lane"], "source_mine")
                self._validate_deep_candidate_doc(doc)

    def test_emit_typed_candidates_no_survivors_returns_zero(self):
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            count, paths = mod.emit_typed_candidates(ws, [])
            self.assertEqual(count, 0)
            self.assertEqual(paths, [])

    def test_run_campaign_emits_typed_candidates_by_default(self):
        """End-to-end: a survivor produced by the full campaign loop is
        also written as a deep_candidate.v1 doc. Default is emit-on.

        Reuses ``KIMI_GOOD_OUTPUT`` from the promotion-gate fixture so
        we exercise the real gate instead of a hand-crafted shape that
        could drift from the gate's expectations."""
        mod = _import_tool()
        runner = _make_runner(
            KIMI_GOOD_OUTPUT, _build_minimax_response(KIMI_GOOD_OUTPUT)
        )
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = mod.run_campaign(
                workspace=ws,
                out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000,
                timeout=10.0,
                max_tokens=4000,
                runner=runner,
            )
            survivors_path = out / "survivors.json"
            self.assertTrue(survivors_path.is_file())
            survivors = json.loads(survivors_path.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(survivors), 1)
            # Typed candidates landed under <workspace>/deep_candidates/
            # as `source_mine_<ts>_<slug>.json` (flat layout per
            # tools/lib/deep_candidate.py:candidate_path).
            typed_dir = ws / "deep_candidates"
            self.assertTrue(
                typed_dir.is_dir(),
                f"expected typed dir at {typed_dir}; "
                f"workspace tree: {sorted(ws.rglob('*'))}",
            )
            typed_files = list(typed_dir.glob("source_mine_*.json"))
            self.assertEqual(
                len(typed_files), len(survivors),
                f"expected one typed doc per survivor, got "
                f"{len(typed_files)} for {len(survivors)} survivors",
            )
            for tf in typed_files:
                self._validate_deep_candidate_doc(
                    json.loads(tf.read_text(encoding="utf-8"))
                )
            promo_json = out / "typed_candidate_promotions.json"
            promo_md = out / "typed_candidate_promotions.md"
            tasks_json = out / "poc_tasks.json"
            tasks_md = out / "poc_tasks.md"
            brief_dir = out / "poc_task_briefs"
            dossier_dir = out / "production_path_dossiers"
            self.assertTrue(promo_json.is_file())
            self.assertTrue(promo_md.is_file())
            self.assertTrue(tasks_json.is_file())
            self.assertTrue(tasks_md.is_file())
            self.assertTrue(brief_dir.is_dir())
            self.assertTrue(dossier_dir.is_dir())
            promo = json.loads(promo_json.read_text(encoding="utf-8"))
            self.assertEqual(promo["candidate_count"], len(survivors))
            self.assertEqual(promo["decision_counts"]["poc_ready"], 0)
            self.assertEqual(promo["decision_counts"]["needs_poc"], len(survivors))
            self.assertEqual(promo["blocker_counts"]["production_path_missing"], len(survivors))
            self.assertEqual(len(json.loads(tasks_json.read_text(encoding="utf-8"))), len(survivors))
            self.assertEqual(len(list(brief_dir.glob("*.md"))), len(survivors))
            self.assertEqual(len(list(dossier_dir.glob("*.json"))), len(survivors))
            self.assertIn("typed_candidate_promotions_json", manifest["artifacts"])
            self.assertIn("typed_candidate_promotions_md", manifest["artifacts"])
            self.assertIn("poc_tasks_json", manifest["artifacts"])
            self.assertIn("poc_tasks_md", manifest["artifacts"])
            self.assertIn("poc_task_briefs_dir", manifest["artifacts"])
            self.assertIn("production_path_dossiers_dir", manifest["artifacts"])

    def test_run_campaign_off_switch_skips_typed_emission(self):
        """`emit_typed=False` must skip the typed emission entirely.
        Survivor JSONL still gets written so existing consumers don't
        break."""
        mod = _import_tool()
        runner = _make_runner(
            KIMI_GOOD_OUTPUT, _build_minimax_response(KIMI_GOOD_OUTPUT)
        )
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            mod.run_campaign(
                workspace=ws,
                out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000,
                timeout=10.0,
                max_tokens=4000,
                runner=runner,
                emit_typed=False,
            )
            self.assertTrue((out / "survivors.json").is_file())
            typed_dir = ws / "deep_candidates"
            # Either the dir doesn't exist OR it has no source_mine
            # records — both satisfy the off-switch contract.
            if typed_dir.is_dir():
                typed_files = list(typed_dir.glob("source_mine_*.json"))
                self.assertEqual(
                    typed_files, [],
                    "no source_mine docs should be written when "
                    "emit_typed=False",
                )

    def test_from_jsonl_standalone_mode(self):
        """The PR #291 standalone CLI path is preserved: run with
        `--from-jsonl` to convert a survivors JSONL into typed records
        without re-running any LLM."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            jsonl = Path(td) / "survivors.jsonl"
            jsonl.write_text(
                json.dumps({
                    "candidate_id": "from-jsonl-claim-0",
                    "bug_shape": "stub-shape",
                    "files": ["src/X.sol"],
                    "description": "stub claim",
                }) + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable, str(TOOL),
                    "--workspace", str(ws),
                    "--from-jsonl", str(jsonl),
                    "--emit-candidate",
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            typed_dir = ws / "deep_candidates"
            self.assertTrue(typed_dir.is_dir())
            typed_files = list(typed_dir.glob("source_mine_*.json"))
            self.assertEqual(len(typed_files), 1)


# ---------------------------------------------------------------------------
# I9 (#320) — auth-failed rollup. Mirrors the no-consent rollup so a
# campaign whose every provider call returned HTTP 401 fails LOUDLY
# instead of emitting "outcome=ok survivors=0".
# ---------------------------------------------------------------------------

class AuthFailedRollupTests(unittest.TestCase):
    """Auth-failed rollup behaviour. The classifier looks for HTTP 401/403
    or `authentication_error` substrings in the dispatch stderr; when
    EVERY non-consent dispatch hit that error, the manifest reports
    `outcome: cannot-run: auth-failed` and the CLI exits non-zero."""

    def _classifier(self):
        return SMC._is_auth_failed_error

    def test_classifier_recognizes_http_401(self) -> None:
        clf = self._classifier()
        self.assertTrue(clf(3, "http-401: authentication_error"))
        self.assertTrue(clf(3, "got HTTP-401 from provider"))

    def test_classifier_recognizes_http_403(self) -> None:
        clf = self._classifier()
        self.assertTrue(clf(3, "http-403: forbidden"))

    def test_classifier_recognizes_provider_message(self) -> None:
        clf = self._classifier()
        # The literal string Kimi returned in the live polymarket run.
        self.assertTrue(clf(3, "API Key appears to be invalid or may have expired"))

    def test_classifier_returns_false_on_success(self) -> None:
        clf = self._classifier()
        self.assertFalse(clf(0, "http-401 in body"))  # rc=0 wins

    def test_classifier_returns_false_for_5xx(self) -> None:
        clf = self._classifier()
        self.assertFalse(clf(3, "http-503: bad gateway"))

    def test_classifier_returns_false_for_no_consent(self) -> None:
        clf = self._classifier()
        # No-consent has its own classifier (existing); auth-failed
        # must not also fire on it (orthogonal counter buckets).
        self.assertFalse(clf(2, "cannot-run: no-consent"))

    def test_all_auth_failed_dispatches_exit_loud(self):
        """All Kimi dispatches return HTTP 401 → manifest outcome
        cannot-run: auth-failed, every counter consistent, survivors=0
        but reported via the auth-failed exit path NOT the silent-zero
        path that I9 was designed to close."""
        def auth_failed_runner(provider, prompt_text, *,
                               audit_dir, timeout, max_tokens,
                               input_is_truncated):
            return (
                3, "",
                '{"reason":"error: dispatch-failed",'
                '"provider":"kimi",'
                '"detail":"http-401: '
                '{\\"error\\":{\\"type\\":\\"authentication_error\\",'
                '\\"message\\":\\"The API Key appears to be invalid'
                ' or may have expired.\\"}}"}',
            )

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=auth_failed_runner,
            )
            self.assertEqual(manifest["outcome"], "cannot-run: auth-failed")
            self.assertGreater(manifest["auth_failed_count"], 0)
            self.assertEqual(
                manifest["auth_failed_count"],
                manifest["dispatch_attempt_count"]
            )
            self.assertEqual(manifest["survivor_count"], 0)

    def test_mixed_auth_failed_warns_but_completes(self):
        """First Kimi dispatch returns 401; second returns success.
        Campaign completes (some real candidates emit), but the manifest
        records the auth_failed count so telemetry can see it."""
        calls = {"kimi": 0}

        def mixed_runner(provider, prompt_text, *,
                         audit_dir, timeout, max_tokens,
                         input_is_truncated):
            if provider == "kimi":
                calls["kimi"] += 1
                if calls["kimi"] == 1:
                    return 3, "", "http-401: authentication_error"
                return 0, KIMI_GOOD_OUTPUT, ""
            return 0, _build_minimax_response(KIMI_GOOD_OUTPUT), ""

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=mixed_runner,
            )
            # Not the "all-failed" path — outcome is the success-path
            # success-message. But the auth_failed counter is recorded.
            self.assertNotEqual(
                manifest.get("outcome"), "cannot-run: auth-failed"
            )
            self.assertEqual(manifest["auth_failed_count"], 1)
            self.assertGreater(
                manifest["dispatch_attempt_count"],
                manifest["auth_failed_count"]
            )

    def test_auth_failed_separate_from_no_consent_count(self):
        """Both counters can fire on the same run without
        double-counting. Auth-failed and no-consent are orthogonal
        buckets (different error classes; different remediation)."""
        sequence: list[tuple[int, str, str]] = [
            (2, "", '{"reason":"cannot-run: no-consent"}'),     # 1st kimi
            (3, "", "http-401: authentication_error"),          # 1st mmx
        ]
        idx = {"i": 0}

        def alternating_runner(provider, prompt_text, *,
                               audit_dir, timeout, max_tokens,
                               input_is_truncated):
            i = idx["i"] % len(sequence)
            idx["i"] += 1
            return sequence[i]

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            # Single-domain workspace so we get exactly 1 kimi + 0 mmx
            # (mmx is skipped when kimi yields no candidates) — i.e.
            # 1 attempt total, no_consent_count=1.
            (ws / "src").mkdir(parents=True, exist_ok=True)
            (ws / "src" / "X.sol").write_text(
                "pragma solidity ^0.8.0; contract X {}",
                encoding="utf-8",
            )
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=alternating_runner,
            )
            # The exact split depends on dispatch order; what matters
            # is the orthogonality: when no-consent fires for one
            # dispatch, the auth-failed counter must NOT also fire
            # for the same dispatch.
            self.assertEqual(
                manifest["no_network_consent_count"]
                + manifest["auth_failed_count"],
                manifest["dispatch_attempt_count"]
                if manifest["dispatch_attempt_count"]
                <= 2 else manifest["dispatch_attempt_count"],
                msg=(
                    f"counters not orthogonal: "
                    f"no-consent={manifest['no_network_consent_count']} "
                    f"auth-failed={manifest['auth_failed_count']} "
                    f"attempts={manifest['dispatch_attempt_count']}"
                ),
            )


# ---------------------------------------------------------------------------
# I14 (#330) — strategic-llm-disallowed rollup. The strategic-LLM policy gate
# (PR #278) refuses any packet whose context mentions "roadmap" / "tier-b" /
# similar policy words unless `--strategic-llm-allowed` is passed. Source-mine
# packets quote the bounty README verbatim, so they trip the gate when the
# README mentions roadmap (real Monetrix incident). Fix: pass
# `--strategic-llm-allowed` from source-mining-campaign.py and add a classifier
# + loud-fail rollup mirroring the I9 (#320) auth-failed pattern.
# ---------------------------------------------------------------------------
class StrategicLLMDisallowedRollupTests(unittest.TestCase):
    """Strategic-LLM-disallowed classifier + rollup behaviour.

    The classifier looks for `cannot-run: strategic-llm-disallowed` in the
    dispatch stderr coupled with rc == EXIT_CANNOT_RUN. When EVERY non-consent
    dispatch hit that error, the manifest reports
    `outcome: cannot-run: strategic-llm-disallowed` and the CLI exits non-zero.
    """

    def _classifier(self):
        return SMC._is_strategic_llm_disallowed_error

    def test_classifier_recognizes_strategic_disallowed_stderr(self) -> None:
        clf = self._classifier()
        # EXIT_CANNOT_RUN is the rc used by llm-dispatch for policy refusals.
        self.assertTrue(clf(SMC.EXIT_CANNOT_RUN, "cannot-run: strategic-llm-disallowed"))

    def test_classifier_recognizes_embedded_strategic_disallowed(self) -> None:
        clf = self._classifier()
        # Real-world: stderr has a multi-line preamble before the marker.
        msg = (
            "[llm-dispatch] policy gate: refusing packet (heuristic match: "
            "context mentions 'roadmap')\n"
            "cannot-run: strategic-llm-disallowed\n"
        )
        self.assertTrue(clf(SMC.EXIT_CANNOT_RUN, msg))

    def test_classifier_returns_false_on_success(self) -> None:
        clf = self._classifier()
        self.assertFalse(clf(0, "cannot-run: strategic-llm-disallowed"))

    def test_classifier_returns_false_for_no_consent(self) -> None:
        clf = self._classifier()
        # Different policy refusal — no-consent has its own classifier.
        self.assertFalse(clf(SMC.EXIT_CANNOT_RUN, "cannot-run: no-consent"))

    def test_classifier_returns_false_for_auth_failed(self) -> None:
        clf = self._classifier()
        # I9 auth-failed must not double-fire with strategic-llm.
        self.assertFalse(clf(3, "http-401: authentication_error"))

    def test_classifier_returns_false_for_other_cannot_run(self) -> None:
        clf = self._classifier()
        self.assertFalse(clf(SMC.EXIT_CANNOT_RUN, "cannot-run: budget-skip"))

    def test_dispatch_argv_includes_strategic_llm_allowed(self) -> None:
        """The fix's behavioural side: every llm-dispatch invocation MUST
        carry --strategic-llm-allowed so the gate doesn't trip on bounty
        READMEs that quote roadmap context. We don't actually exec the
        dispatcher — we substitute subprocess.run on the SMC module and
        assert the argv passed to llm-dispatch.py."""
        captured: list[list[str]] = []

        class _StubCompleted:
            def __init__(self) -> None:
                self.stdout = ""
                self.stderr = ""
                self.returncode = 0

        def fake_run(argv, *args, **kwargs):
            captured.append(list(argv))
            return _StubCompleted()

        # _default_runner uses `subprocess.run` resolved through the SMC
        # module's import binding. Patch THAT binding so we don't poison
        # the global subprocess module for parallel tests.
        orig = SMC.subprocess.run
        SMC.subprocess.run = fake_run
        try:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                workspace = root / "workspace"
                audit_dir = root / "source_mining" / "campaign" / "agent_outputs"
                workspace.mkdir()
                SMC._default_runner(
                    "kimi", "<packet text>",
                    audit_dir=audit_dir, timeout=5.0,
                    max_tokens=1000, input_is_truncated=False,
                    workspace=workspace,
                )
        finally:
            SMC.subprocess.run = orig

        self.assertTrue(captured, "expected at least one dispatch invocation")
        flattened = "\n".join(" ".join(argv) for argv in captured)
        self.assertIn("dispatch-preflight.py", flattened)
        self.assertIn("--template source-extract", flattened)
        self.assertIn("--audit-log", flattened)
        argv = captured[0]
        self.assertIn("--workspace", argv)
        self.assertEqual(Path(argv[argv.index("--workspace") + 1]), workspace.resolve())
        self.assertNotEqual(Path(argv[argv.index("--workspace") + 1]), audit_dir.parent.resolve())
        self.assertIn("--forward", flattened)
        self.assertIn("--strategic-llm-allowed", flattened)

    def test_all_strategic_disallowed_dispatches_exit_loud(self):
        """All Kimi dispatches return strategic-llm-disallowed → manifest
        outcome `cannot-run: strategic-llm-disallowed`, every counter
        consistent, survivors=0 but reported via the loud-fail exit path
        NOT the silent-zero `outcome: ok survivors=0` path that I14 closes.
        Mirrors the I9 auth-failed loud-fail pattern."""
        def disallowed_runner(provider, prompt_text, *,
                              audit_dir, timeout, max_tokens,
                              input_is_truncated):
            return (
                SMC.EXIT_CANNOT_RUN, "",
                "cannot-run: strategic-llm-disallowed",
            )

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=disallowed_runner,
            )
            self.assertEqual(
                manifest["outcome"],
                "cannot-run: strategic-llm-disallowed",
            )
            self.assertGreater(manifest["strategic_disallowed_count"], 0)
            self.assertEqual(
                manifest["strategic_disallowed_count"],
                manifest["dispatch_attempt_count"],
            )
            self.assertEqual(manifest["survivor_count"], 0)
            self.assertIn(
                "strategic_disallowed_domains",
                manifest,
                "domains list must be present for triage",
            )

    def test_mixed_strategic_disallowed_warns_but_completes(self):
        """First Kimi dispatch returns strategic-llm-disallowed; second
        returns success. Campaign completes (real candidates emit), but
        the manifest records the strategic_disallowed_count for telemetry."""
        calls = {"kimi": 0}

        def mixed_runner(provider, prompt_text, *,
                         audit_dir, timeout, max_tokens,
                         input_is_truncated):
            if provider == "kimi":
                calls["kimi"] += 1
                if calls["kimi"] == 1:
                    return (
                        SMC.EXIT_CANNOT_RUN, "",
                        "cannot-run: strategic-llm-disallowed",
                    )
                return 0, KIMI_GOOD_OUTPUT, ""
            return 0, _build_minimax_response(KIMI_GOOD_OUTPUT), ""

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=mixed_runner,
            )
            # Not the "all-failed" path — campaign survived.
            self.assertNotEqual(
                manifest.get("outcome"),
                "cannot-run: strategic-llm-disallowed",
            )
            self.assertEqual(manifest["strategic_disallowed_count"], 1)
            self.assertGreater(
                manifest["dispatch_attempt_count"],
                manifest["strategic_disallowed_count"],
            )

    def test_strategic_disallowed_orthogonal_to_other_buckets(self):
        """strategic_disallowed_count must NOT also bump the auth_failed
        or no_network_consent counters (different policy refusal classes
        with different remediations)."""
        def disallowed_runner(provider, prompt_text, *,
                              audit_dir, timeout, max_tokens,
                              input_is_truncated):
            return (
                SMC.EXIT_CANNOT_RUN, "",
                "cannot-run: strategic-llm-disallowed",
            )

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=disallowed_runner,
            )
            self.assertGreater(manifest["strategic_disallowed_count"], 0)
            self.assertEqual(manifest["auth_failed_count"], 0)
            self.assertEqual(manifest["no_network_consent_count"], 0)


# ---------------------------------------------------------------------------
# I11 (#326) — budget-skip rollup. The rolling-window LLM budget guard
# (active ceiling comes from tools/calibration/llm_budget.json; full opt-out
# via AUDITOOOR_LLM_BUDGET_GUARD=0)
# can refuse every dispatch in a campaign run that started AFTER prior
# campaigns spent the budget. Without I11, the campaign reports
# `outcome: ok survivors=0` silently. With I11 it reports
# `outcome: cannot-run: budget-exhausted` with a remediation hint and
# the CLI exits non-zero. Mirrors the I9 (auth-failed) and I14
# (strategic-llm-disallowed) loud-fail patterns.
# ---------------------------------------------------------------------------
class BudgetSkipRollupTests(unittest.TestCase):
    """Budget-skip classifier + rollup behaviour."""

    def _classifier(self):
        return SMC._is_budget_skip_error

    def test_classifier_recognizes_budget_skip_substring(self) -> None:
        clf = self._classifier()
        # Real-world stderr from the dispatcher fallback chain.
        msg = (
            "{\"reason\": \"error: dispatch-failed\", \"detail\": "
            "\"all providers exhausted\", \"fallback_reasons\": "
            "[\"kimi: budget-skip: tokens budget exhausted: "
            "132458/60000 in last 60min\"]}"
        )
        self.assertTrue(clf(3, msg))

    def test_classifier_recognizes_uppercase_substring(self) -> None:
        clf = self._classifier()
        # The classifier is case-insensitive on the substring (defensive
        # against future formatting changes in the dispatcher).
        self.assertTrue(clf(2, "Budget-Skip: tokens budget exhausted: 1/0"))

    def test_classifier_returns_false_on_success(self) -> None:
        clf = self._classifier()
        self.assertFalse(clf(0, "budget-skip: irrelevant since rc=0"))

    def test_classifier_returns_false_for_no_consent(self) -> None:
        clf = self._classifier()
        self.assertFalse(clf(SMC.EXIT_CANNOT_RUN, "cannot-run: no-consent"))

    def test_classifier_returns_false_for_auth_failed(self) -> None:
        clf = self._classifier()
        # I9 auth-failed is a different class.
        self.assertFalse(clf(3, "http-401: authentication_error"))

    def test_classifier_returns_false_for_strategic_disallowed(self) -> None:
        clf = self._classifier()
        # I14 strategic-disallowed is a different class.
        self.assertFalse(clf(SMC.EXIT_CANNOT_RUN, "cannot-run: strategic-llm-disallowed"))

    def test_all_budget_skipped_dispatches_exit_loud(self):
        """All Kimi dispatches return budget-skip → manifest outcome
        cannot-run: budget-exhausted, every counter consistent,
        survivors=0 but reported via the loud-fail exit path NOT the
        silent-zero path I11 closes."""
        def budget_skip_runner(provider, prompt_text, *,
                               audit_dir, timeout, max_tokens,
                               input_is_truncated):
            return (
                3, "",
                "kimi: budget-skip: tokens budget exhausted: "
                "132458/60000 in last 60min",
            )

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=budget_skip_runner,
            )
            self.assertEqual(manifest["outcome"], "cannot-run: budget-exhausted")
            self.assertGreater(manifest["budget_skip_count"], 0)
            self.assertEqual(
                manifest["budget_skip_count"],
                manifest["dispatch_attempt_count"],
            )
            self.assertEqual(manifest["survivor_count"], 0)
            # Remediation hint is part of the manifest so callers (and
            # operators) get an actionable message — not just an opaque
            # outcome string.
            self.assertIn("remediation", manifest)
            self.assertIn("AUDITOOOR_LLM_BUDGET_GUARD", manifest["remediation"])
            self.assertIn("budget_skip_domains", manifest)

    def test_mixed_budget_skip_warns_but_completes(self):
        """First Kimi dispatch returns budget-skip; second succeeds.
        Campaign completes, but the manifest records the count for
        telemetry."""
        calls = {"kimi": 0}

        def mixed_runner(provider, prompt_text, *,
                         audit_dir, timeout, max_tokens,
                         input_is_truncated):
            if provider == "kimi":
                calls["kimi"] += 1
                if calls["kimi"] == 1:
                    return (
                        3, "",
                        "kimi: budget-skip: tokens budget exhausted",
                    )
                return 0, KIMI_GOOD_OUTPUT, ""
            return 0, _build_minimax_response(KIMI_GOOD_OUTPUT), ""

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=mixed_runner,
            )
            # Not the "all-failed" path — campaign survived.
            self.assertNotEqual(
                manifest.get("outcome"),
                "cannot-run: budget-exhausted",
            )
            self.assertEqual(manifest["budget_skip_count"], 1)
            self.assertGreater(
                manifest["dispatch_attempt_count"],
                manifest["budget_skip_count"],
            )

    def test_budget_skip_orthogonal_to_other_buckets(self):
        """budget_skip_count must NOT also bump the auth_failed,
        no_network_consent, or strategic_disallowed counters."""
        def budget_skip_runner(provider, prompt_text, *,
                               audit_dir, timeout, max_tokens,
                               input_is_truncated):
            return (
                3, "",
                "kimi: budget-skip: tokens budget exhausted",
            )

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=budget_skip_runner,
            )
            self.assertGreater(manifest["budget_skip_count"], 0)
            self.assertEqual(manifest["auth_failed_count"], 0)
            self.assertEqual(manifest["no_network_consent_count"], 0)
            self.assertEqual(manifest["strategic_disallowed_count"], 0)


# ---------------------------------------------------------------------------
# I18 (#335) — `--ext` flag enables non-Solidity workspaces (Rust/Soroban,
# Cairo, Move, Vyper). Without the flag, source-mining-campaign hardcodes
# `*.sol` everywhere and silently produces 0 domains on Rust workspaces.
# This test class covers: extension-aware walker, parameterised cite
# regex, default-Solidity backwards compatibility, and the ext field
# being recorded in the manifest.
# ---------------------------------------------------------------------------
class ExtFlagTests(unittest.TestCase):
    """`--ext` flag and ext-parameter plumbing through slicer + cite
    validator + manifest. Hermetic: scaffolds temp workspaces with both
    `.sol` and `.rs` files."""

    def _scaffold_rs_workspace(self, root: Path) -> Path:
        ws = root / "ws"
        # Rust/Soroban canonical layout: contracts/<crate>/src/*.rs
        crate = ws / "contracts" / "kinetic-router" / "src"
        crate.mkdir(parents=True, exist_ok=True)
        (crate / "router.rs").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pub fn supply() {}\npub fn borrow() {}\n",
            encoding="utf-8",
        )
        (crate / "calculation.rs").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pub fn calc_health_factor() -> u128 { 0 }\n",
            encoding="utf-8",
        )
        # OOS test harness — should be skipped by the slicer.
        tests = ws / "tests"
        tests.mkdir(exist_ok=True)
        (tests / "harness.rs").write_text("// test\n", encoding="utf-8")
        return ws

    def test_slicer_picks_rs_files_when_ext_rs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = self._scaffold_rs_workspace(Path(td))
            domains = SMC.slice_domains(ws, ext="rs")
            self.assertGreater(len(domains), 0, f"slicer returned no domains: {domains}")
            # Both router.rs and calculation.rs should appear somewhere.
            all_files = sum(domains.values(), [])
            self.assertTrue(
                any("router.rs" in f for f in all_files),
                f"router.rs missing: {all_files}",
            )
            self.assertTrue(
                any("calculation.rs" in f for f in all_files),
                f"calculation.rs missing: {all_files}",
            )
            # tests/harness.rs MUST be excluded.
            self.assertFalse(
                any("harness.rs" in f for f in all_files),
                "test harness should be excluded",
            )

    def test_slicer_skips_rs_when_default_ext_sol(self) -> None:
        """Backwards-compat: default ext='sol' on a Rust workspace
        returns 0 domains (which is correct — no .sol files exist)."""
        with tempfile.TemporaryDirectory() as td:
            ws = self._scaffold_rs_workspace(Path(td))
            domains = SMC.slice_domains(ws)  # default ext
            self.assertEqual(domains, {})

    def test_slicer_picks_sol_files_unchanged_when_default(self) -> None:
        """Backwards-compat: existing Solidity workspaces still work
        without setting --ext."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            domains = SMC.slice_domains(ws)
            self.assertGreater(len(domains), 0)

    def test_line_cite_regex_accepts_rs_cite(self) -> None:
        rs_cite = {"source_files": ["src/contracts/router.rs:42-58"]}
        self.assertTrue(SMC._has_line_cite(rs_cite, ext="rs"))
        # Without ext=rs, the same cite is rejected.
        self.assertFalse(SMC._has_line_cite(rs_cite))  # default ext=sol

    def test_line_cite_regex_accepts_sol_cite_default(self) -> None:
        """Default ext='sol' still validates the original cite shape."""
        sol_cite = {"source_files": ["src/Vault.sol:100"]}
        self.assertTrue(SMC._has_line_cite(sol_cite))
        self.assertTrue(SMC._has_line_cite(sol_cite, ext="sol"))

    def test_line_cite_regex_rejects_bare_path(self) -> None:
        self.assertFalse(SMC._has_line_cite({"source_files": ["src/Foo.sol"]}))
        self.assertFalse(SMC._has_line_cite({"source_files": ["src/Foo.rs"]}, ext="rs"))

    def test_line_cite_regex_for_unusual_ext(self) -> None:
        """Cite regex factory accepts other extensions on demand
        (cairo, move, vy, etc.)."""
        cairo_cite = {"source_files": ["src/Token.cairo:120-145"]}
        self.assertTrue(SMC._has_line_cite(cairo_cite, ext="cairo"))
        # cairo cite must NOT validate as .rs or .sol.
        self.assertFalse(SMC._has_line_cite(cairo_cite, ext="rs"))
        self.assertFalse(SMC._has_line_cite(cairo_cite))

    def test_run_campaign_records_ext_in_manifest(self) -> None:
        """The manifest carries the `ext` field for traceability — so
        downstream consumers (engage, telemetry, dashboards) can tell
        which extension a campaign mined."""
        def good_runner(provider, prompt_text, *,
                        audit_dir, timeout, max_tokens,
                        input_is_truncated):
            if provider == "kimi":
                return 0, KIMI_GOOD_OUTPUT, ""
            return 0, _build_minimax_response(KIMI_GOOD_OUTPUT), ""

        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_ws(Path(td) / "ws")
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=good_runner,
                ext="sol",
            )
            self.assertEqual(manifest.get("ext"), "sol")

    def test_run_campaign_with_ext_rs_filters_cites(self) -> None:
        """A campaign with --ext rs must REJECT Kimi candidates citing
        `.sol:LINE` (since those don't match the workspace's extension)
        and ACCEPT candidates citing `.rs:LINE`."""
        rs_cite_payload = json.dumps({
            "candidate_id": "rs-candidate-001",
            "source_files": ["contracts/router/src/lib.rs:42-58"],
            "bug_shape": "missing require_auth",
            "reachable_non_privileged_path": "anyone can call admin_fn",
            "required_state": "no role grants checked",
            "impact_hypothesis": "ownership takeover",
            "severity_lower_bound": "MEDIUM",
            "next_check": "grep require_auth in router/src/lib.rs",
        })

        def rs_runner(provider, prompt_text, *,
                      audit_dir, timeout, max_tokens,
                      input_is_truncated):
            if provider == "kimi":
                return 0, rs_cite_payload, ""
            return 0, _build_minimax_response(rs_cite_payload), ""

        with tempfile.TemporaryDirectory() as td:
            ws = self._scaffold_rs_workspace(Path(td))
            out = Path(td) / "out"
            manifest = SMC.run_campaign(
                workspace=ws, out_dir=out,
                providers=("kimi", "minimax"),
                packet_budget=100_000, timeout=10.0, max_tokens=4000,
                runner=rs_runner,
                ext="rs",
            )
            # The .rs cite should pass the line-cite gate (because we
            # ran with ext=rs). The candidate makes it to survivors or
            # rejected based on Minimax verdict.
            self.assertEqual(manifest.get("ext"), "rs")
            # Domains were sliced from rs files.
            self.assertGreater(manifest["domain_count"], 0)
            survivors = json.loads((out / "survivors.json").read_text(encoding="utf-8"))
            self.assertEqual([s["candidate_id"] for s in survivors], ["rs-candidate-001"])
            survivor = survivors[0]
            self.assertNotIn("severity_lower_bound", survivor)
            self.assertEqual(survivor["severity"], "none")
            self.assertEqual(survivor["selected_impact"], "")
            self.assertEqual(survivor["submission_posture"], "NOT_SUBMIT_READY")
            self.assertTrue(survivor["impact_contract_required"])
            self.assertEqual(
                survivor["provider_non_authoritative_claims"]["severity_or_impact"][
                    "severity_lower_bound"
                ],
                "MEDIUM",
            )


if __name__ == "__main__":
    unittest.main()
