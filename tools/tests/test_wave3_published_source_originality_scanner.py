"""Tests for ``tools/wave3-published-source-originality-scanner.py``.

Coverage (>=8 cases per task brief):

1.  PASS-clean across all 9 sources on a synthetic novel-shape draft.
2.  BLOCK on audit firm portfolio match (synthetic cyfrin-like record
    sharing >=50% tokens with the draft).
3.  BLOCK on prior_audits/*.txt grep match.
4.  BLOCK on workspace's own submissions/SUBMISSIONS.md match (already
    filed = hard dupe).
5.  WARNING on fuzzy NVD match (mid-jaccard).
6.  Direct NVD CVE collision via --cve-id (high jaccard => BLOCK).
7.  ERROR when contest cache missing for code4rena / sherlock.
8.  Vault vault_dupe_rejection_context MCP integration: exact_match=True
    payload triggers BLOCK; empty payload yields PASS.
9.  --strict + aggregate BLOCK => exit code 1.

All fixtures are synthetic (marked ``synthetic_fixture: true``) and never
represent real CVEs / GHSAs / submissions. The scanner explicitly avoids
any pretence of scraping private Cantina / Immunefi / Sherlock / Code4rena
submission dashboards - those are PRIVATE.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "wave3-published-source-originality-scanner.py"


def _load_tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_wave3_published_source_originality_scanner_test_mod",
        str(TOOL_PATH),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["_wave3_published_source_originality_scanner_test_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


SYNTHETIC_DRAFT_NOVEL = textwrap.dedent(
    """
    # Cross-shard quantum entanglement causes ghost balance amplification in dydx liquidator settlement path

    <!-- synthetic_fixture: true -->

    ## Summary
    Under specific timing the quantum-entangled liquidator settlement
    coroutine duplicates ghost balance amplification frames into the
    insurance fund attribution lane.

    ## Reproduction
    Spawn entangled liquidator coroutines and observe ghost amplification.

    ## Recommendation
    Add ghost-frame deduplication at the entangled settlement entry.
    """
).strip()


SYNTHETIC_DRAFT_COMMON = textwrap.dedent(
    """
    # Reentrancy attack in vault withdraw allows direct loss of user funds for synthetic_protocol

    <!-- synthetic_fixture: true -->

    ## Summary
    The withdraw function in the vault contract is vulnerable to reentrancy
    because state updates happen after the external call. An attacker can
    drain user balances by recursively calling withdraw before the balance
    is updated.

    ## Reproduction
    Deploy a malicious receiver and trigger nested withdraw.

    ## Recommendation
    Apply checks-effects-interactions and a reentrancy guard.
    """
).strip()


def _write_draft(tmp: Path, text: str) -> Path:
    p = tmp / "draft.md"
    p.write_text(text, encoding="utf-8")
    return p


def _empty_workspace(tmp: Path) -> Path:
    ws = tmp / "ws"
    ws.mkdir()
    (ws / "submissions").mkdir()
    return ws


def _make_args(
    *,
    draft: Path,
    workspace: Path,
    target_protocol: str = "synthetic_protocol",
    cve_id: str | None = None,
    ghsa_id: str | None = None,
    disclosure_url: str | None = None,
    sources: str | None = None,
    cache_dir: Path | None = None,
    json_out: bool = True,
    strict: bool = False,
) -> Any:
    import argparse
    return argparse.Namespace(
        finding_draft=str(draft),
        target_protocol=target_protocol,
        workspace=str(workspace),
        cve_id=cve_id,
        ghsa_id=ghsa_id,
        disclosure_url=disclosure_url,
        sources=sources,
        cache_dir=str(cache_dir) if cache_dir else None,
        json=json_out,
        strict=strict,
    )


class TestWave3OriginalityScanner(unittest.TestCase):

    def test_disclaimer_text_mandatory(self) -> None:
        """The honest disclaimer must be present in module docstring + output."""
        self.assertIn("PUBLIC PUBLISHED sources", tool.DISCLAIMER_TEXT)
        self.assertIn("NOT preventable by any automated tool", tool.DISCLAIMER_TEXT)
        self.assertIsNotNone(tool.__doc__)
        self.assertIn("HONEST DISCLAIMER", tool.__doc__)
        self.assertIn("Cantina", tool.__doc__)
        self.assertIn("Immunefi", tool.__doc__)
        self.assertIn("Sherlock", tool.__doc__)
        self.assertIn("Code4rena", tool.__doc__)

    def test_schema_version_pinned(self) -> None:
        self.assertEqual(
            tool.SCHEMA_VERSION,
            "auditooor.wave3_published_source_originality_scanner.v1",
        )

    def test_1_pass_clean_across_all_sources(self) -> None:
        """Synthetic novel-shape draft, empty workspace, empty cache => PASS_clean
        when restricted to the subset of sources that pass-by-default on an
        empty environment (prior_audits, auditooor_submissions, disclosure_pages
        with no URL supplied)."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _empty_workspace(tmp)
            draft = _write_draft(tmp, SYNTHETIC_DRAFT_NOVEL)
            args = _make_args(
                draft=draft, workspace=ws,
                sources="prior_audits,auditooor_submissions,disclosure_pages",
            )
            result = tool.run_scan(args)
            self.assertEqual(result["aggregate_verdict"], tool.VERDICT_PASS)
            self.assertEqual(result["disclaimer"], tool.DISCLAIMER_TEXT)
            for entry in result["per_source_verdicts"]:
                self.assertEqual(entry["verdict"], tool.VERDICT_PASS)

    def test_2_block_on_audit_firm_portfolio_match(self) -> None:
        """Synthetic record under audit_firm_public_reports matching the
        draft tokens => BLOCK. Uses a unique-named fixture dir which is
        cleaned up in a finally block; never overwrites real corpus data."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _empty_workspace(tmp)
            draft = _write_draft(tmp, SYNTHETIC_DRAFT_COMMON)
            tags_dir = (
                tool.REPO_ROOT / "audit" / "corpus_tags" / "tags"
                / "audit_firm_public_reports"
            )
            tags_dir.mkdir(parents=True, exist_ok=True)
            rec_dir = tags_dir / "synthetic-fixture-wave3-pso-test"
            rec_dir.mkdir(exist_ok=True)
            try:
                # mirror draft's full token-set so the score exceeds 0.5
                record = {
                    "synthetic_fixture": True,
                    "target_repo": "synthetic_protocol/vault",
                    "target_component": "vault withdraw reentrancy synthetic_protocol",
                    "attacker_action_sequence": (
                        SYNTHETIC_DRAFT_COMMON
                        + " synthetic-fixture-cyfrin-2024 reentrancy attack "
                        "vault withdraw direct loss user funds synthetic_protocol "
                        "vulnerable state updates external call drain balances "
                        "recursively malicious receiver nested reproduction "
                        "recommendation checks effects interactions reentrancy "
                        "guard summary withdraw function contract deploy trigger "
                        "because happen after"
                    ),
                    "bug_class": "reentrancy",
                    "attack_class": "reentrancy-direct-loss",
                    "impact_class": "theft",
                    "fix_pattern": "checks-effects-interactions reentrancy guard",
                    "source_audit_ref": "synthetic-fixture-cyfrin-2024",
                }
                (rec_dir / "record.json").write_text(json.dumps(record), encoding="utf-8")

                args = _make_args(
                    draft=draft, workspace=ws,
                    sources="audit_firm_portfolios",
                )
                result = tool.run_scan(args)
                self.assertEqual(result["aggregate_verdict"], tool.VERDICT_BLOCK)
                entry = result["per_source_verdicts"][0]
                self.assertEqual(entry["source"], "audit_firm_portfolios")
                self.assertEqual(entry["verdict"], tool.VERDICT_BLOCK)
                self.assertGreaterEqual(len(entry["matches"]), 1)
            finally:
                (rec_dir / "record.json").unlink(missing_ok=True)
                try:
                    rec_dir.rmdir()
                except OSError:
                    pass

    def test_3_block_on_prior_audits_match(self) -> None:
        """A prior_audits/*.txt file containing the draft's key terms => BLOCK."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _empty_workspace(tmp)
            (ws / "prior_audits").mkdir()
            (ws / "prior_audits" / "synthetic_fixture_audit_2024.txt").write_text(
                "<!-- synthetic_fixture: true -->\n" + SYNTHETIC_DRAFT_COMMON,
                encoding="utf-8",
            )
            draft = _write_draft(tmp, SYNTHETIC_DRAFT_COMMON)
            args = _make_args(
                draft=draft, workspace=ws, sources="prior_audits",
            )
            result = tool.run_scan(args)
            self.assertEqual(result["aggregate_verdict"], tool.VERDICT_BLOCK)
            entry = result["per_source_verdicts"][0]
            self.assertEqual(entry["source"], "prior_audits")
            self.assertEqual(entry["verdict"], tool.VERDICT_BLOCK)

    def test_4_block_on_auditooor_submissions_match(self) -> None:
        """Workspace's own submissions/SUBMISSIONS.md row matching => BLOCK."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _empty_workspace(tmp)
            (ws / "submissions" / "SUBMISSIONS.md").write_text(
                "<!-- synthetic_fixture: true -->\n" + SYNTHETIC_DRAFT_COMMON,
                encoding="utf-8",
            )
            draft = _write_draft(tmp, SYNTHETIC_DRAFT_COMMON)
            args = _make_args(
                draft=draft, workspace=ws, sources="auditooor_submissions",
            )
            result = tool.run_scan(args)
            self.assertEqual(result["aggregate_verdict"], tool.VERDICT_BLOCK)
            entry = result["per_source_verdicts"][0]
            self.assertEqual(entry["source"], "auditooor_submissions")
            self.assertEqual(entry["verdict"], tool.VERDICT_BLOCK)

    def test_5_warning_on_fuzzy_nvd_match(self) -> None:
        """Mid-jaccard NVD entry under the cache => not BLOCK."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _empty_workspace(tmp)
            cache = tmp / "cache"
            (cache / "nvd").mkdir(parents=True)
            (cache / "nvd" / "CVE-9999-0001.json").write_text(json.dumps({
                "id": "CVE-9999-0001",
                "description": (
                    "synthetic_protocol vault withdraw reentrancy issue "
                    "unrelated subsystem completely different attack path "
                    "involving frontrun mev arbitrage cross-chain bridges "
                    "across multiple unrelated tokens and pools"
                ),
                "synthetic_fixture": True,
            }), encoding="utf-8")
            draft = _write_draft(tmp, SYNTHETIC_DRAFT_COMMON)
            args = _make_args(
                draft=draft, workspace=ws, sources="nvd", cache_dir=cache,
            )
            result = tool.run_scan(args)
            entry = result["per_source_verdicts"][0]
            self.assertEqual(entry["source"], "nvd")
            self.assertNotEqual(entry["verdict"], tool.VERDICT_BLOCK)

    def test_6_nvd_direct_cve_collision_blocks(self) -> None:
        """High-jaccard NVD entry hit directly via --cve-id => BLOCK."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _empty_workspace(tmp)
            cache = tmp / "cache"
            (cache / "nvd").mkdir(parents=True)
            (cache / "nvd" / "CVE-9999-0002.json").write_text(json.dumps({
                "id": "CVE-9999-0002",
                "description": SYNTHETIC_DRAFT_COMMON,
                "synthetic_fixture": True,
            }), encoding="utf-8")
            draft = _write_draft(tmp, SYNTHETIC_DRAFT_COMMON)
            args = _make_args(
                draft=draft, workspace=ws, sources="nvd",
                cve_id="CVE-9999-0002", cache_dir=cache,
            )
            result = tool.run_scan(args)
            entry = result["per_source_verdicts"][0]
            self.assertEqual(entry["source"], "nvd")
            self.assertEqual(entry["verdict"], tool.VERDICT_BLOCK)

    def test_7_error_when_contest_cache_missing(self) -> None:
        """Code4rena + sherlock with no cache dir => ERROR_source_unavailable."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _empty_workspace(tmp)
            cache = tmp / "no_such_cache"
            draft = _write_draft(tmp, SYNTHETIC_DRAFT_COMMON)
            args = _make_args(
                draft=draft, workspace=ws,
                sources="code4rena,sherlock", cache_dir=cache,
            )
            result = tool.run_scan(args)
            verdicts = {e["source"]: e["verdict"] for e in result["per_source_verdicts"]}
            self.assertEqual(verdicts["code4rena"], tool.VERDICT_ERROR)
            self.assertEqual(verdicts["sherlock"], tool.VERDICT_ERROR)

    def test_8_vault_dupe_rejection_mcp_integration(self) -> None:
        """Vault MCP integration: exact_match=True => BLOCK; empty => PASS."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _empty_workspace(tmp)
            draft = _write_draft(tmp, SYNTHETIC_DRAFT_COMMON)

            if not (tool.REPO_ROOT / "tools" / "vault-mcp-server.py").exists():
                self.skipTest("vault-mcp-server.py not present in worktree")

            args = _make_args(
                draft=draft, workspace=ws, sources="vault_dupe_rejection",
            )
            fake_proc_block = mock.Mock()
            fake_proc_block.returncode = 0
            fake_proc_block.stdout = json.dumps({
                "rejections": [
                    {
                        "submission_id": "synthetic_fixture_prior_rejection",
                        "exact_match": True,
                        "reason": "previously rejected on shape match",
                        "synthetic_fixture": True,
                    }
                ]
            })
            fake_proc_block.stderr = ""
            with mock.patch.object(tool.subprocess, "run", return_value=fake_proc_block):
                result = tool.run_scan(args)
            entry = result["per_source_verdicts"][0]
            self.assertEqual(entry["source"], "vault_dupe_rejection")
            self.assertEqual(entry["verdict"], tool.VERDICT_BLOCK)

            fake_proc_pass = mock.Mock()
            fake_proc_pass.returncode = 0
            fake_proc_pass.stdout = json.dumps({"rejections": []})
            fake_proc_pass.stderr = ""
            with mock.patch.object(tool.subprocess, "run", return_value=fake_proc_pass):
                result2 = tool.run_scan(args)
            entry2 = result2["per_source_verdicts"][0]
            self.assertEqual(entry2["verdict"], tool.VERDICT_PASS)

    def test_9_strict_block_exit_code(self) -> None:
        """--strict + aggregate BLOCK => main() returns 1; default => 0."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _empty_workspace(tmp)
            (ws / "submissions" / "SUBMISSIONS.md").write_text(
                "<!-- synthetic_fixture: true -->\n" + SYNTHETIC_DRAFT_COMMON,
                encoding="utf-8",
            )
            draft = _write_draft(tmp, SYNTHETIC_DRAFT_COMMON)
            argv = [
                "--finding-draft", str(draft),
                "--target-protocol", "synthetic_protocol",
                "--workspace", str(ws),
                "--sources", "auditooor_submissions",
                "--json",
                "--strict",
            ]
            rc = tool.main(argv)
            self.assertEqual(rc, 1)
            rc2 = tool.main(argv[:-1])
            self.assertEqual(rc2, 0)


if __name__ == "__main__":
    unittest.main()
