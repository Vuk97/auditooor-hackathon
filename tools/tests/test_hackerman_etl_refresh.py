from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-refresh.py"
VERDICT_FIXTURES = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_etl_verdict_tags"
GIT_FIXTURES = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_etl_from_git_mining" / "reports"
CORPUS_FIXTURES = REPO_ROOT / "tools" / "tests" / "fixtures" / "corpus_mined_etl"
PRIOR_FIXTURES = REPO_ROOT / "tools" / "tests" / "fixtures" / "prior_audit_etl" / "workspaces"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_etl_refresh", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _record(record_id: str, source_ref: str) -> str:
    return f"""
schema_version: auditooor.hackerman_record.v1
record_id: {record_id}
source_audit_ref: {source_ref}
target_domain: lending
target_language: solidity
target_repo: example/protocol
target_component: Vault.deposit
function_shape:
  raw_signature: "function deposit(uint256 assets) external"
  shape_tags:
    - external-deposit
bug_class: accounting
attack_class: state-accounting-drift
attacker_role: unprivileged
attacker_action_sequence: "deposit through the stale accounting path"
required_preconditions:
  - stale accounting state exists
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: refresh accounting before minting shares
fix_anti_pattern_avoided: stale accounting state
severity_at_finding: medium
year: 2026
cross_language_analogues: []
related_records: []
""".lstrip()


class HackermanEtlRefreshTests(unittest.TestCase):
    def test_collision_report_allows_same_content_and_flags_different_content(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory(prefix="hackerman-refresh-collisions-") as tmp:
            root = Path(tmp)
            stage = root / "stage"
            live = root / "live"
            stage.mkdir()
            live.mkdir()
            (stage / "same.yaml").write_text("a: 1\n", encoding="utf-8")
            (live / "same.yaml").write_text("a: 1\n", encoding="utf-8")
            (stage / "different.yaml").write_text("a: 2\n", encoding="utf-8")
            (live / "different.yaml").write_text("a: 3\n", encoding="utf-8")
            (stage / "new.yaml").write_text("a: 4\n", encoding="utf-8")

            report = mod.collision_report(stage, live)

            self.assertEqual(report["new"], 1)
            self.assertEqual(report["same_content_existing"], 1)
            self.assertEqual(report["different_content_collisions"], 1)
            self.assertEqual(report["different_collision_files"], ["different.yaml"])

    def test_identity_collision_report_flags_duplicate_records_and_live_conflicts(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory(prefix="hackerman-refresh-identity-") as tmp:
            root = Path(tmp)
            stage = root / "stage"
            live = root / "live"
            stage.mkdir()
            live.mkdir()
            (stage / "one.yaml").write_text(_record("rec/one", "audit:one"), encoding="utf-8")
            (stage / "dupe.yaml").write_text(_record("rec/one", "audit:two"), encoding="utf-8")
            (stage / "live-conflict.yaml").write_text(_record("rec/three", "audit:live"), encoding="utf-8")
            (live / "old.yaml").write_text(_record("rec/old", "audit:live"), encoding="utf-8")

            report = mod.identity_collision_report(stage, live)

            self.assertEqual(report["staged_duplicate_identities"], 1)
            self.assertEqual(report["live_identity_conflicts"], 1)
            self.assertIn("record_id:rec/one", report["staged_duplicate_identity_files"][0])
            self.assertIn("source_audit_ref:audit:live", report["live_identity_conflict_files"][0])

    def test_cli_dry_run_stages_valid_records_without_copying(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-refresh-dry-") as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            index_dir = root / "index"
            stage_dir = root / "stage"
            tag_dir.mkdir()
            index_dir.mkdir()
            shutil.copy(VERDICT_FIXTURES / "legacy_v2_oracle.yaml", tag_dir / "legacy_v2_oracle.yaml")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--tag-dir",
                    str(tag_dir),
                    "--index-dir",
                    str(index_dir),
                    "--reports-dir",
                    str(GIT_FIXTURES),
                    "--corpus-dir",
                    str(CORPUS_FIXTURES),
                    "--skip-findings-go",
                    "--skip-solodit-specs",
                    "--skip-solidity-fork-patterns",
                    "--workspace",
                    str(PRIOR_FIXTURES / "alpha"),
                    "--stage-dir",
                    str(stage_dir),
                    "--dry-run",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertTrue(payload["dry_run"])
            self.assertEqual(payload["copied"], 0)
            self.assertGreaterEqual(payload["staged_yaml"], 10)
            self.assertEqual(payload["collisions"]["different_content_collisions"], 0)
            self.assertTrue(list(stage_dir.glob("*.yaml")))
            self.assertFalse(list(index_dir.glob("by_*.jsonl")))

    def test_cli_dry_run_can_stage_solidity_fork_patterns_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-refresh-patterns-") as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            index_dir = root / "index"
            patterns_dir = root / "patterns" / "liquity-fork"
            stage_dir = root / "stage"
            tag_dir.mkdir()
            index_dir.mkdir()
            patterns_dir.mkdir(parents=True)
            (patterns_dir / "redemption-hint.md").write_text(
                """
# Liquity redemption hint stale ordering

- family: liquity-fork
- target: liquity/dev
- trigger-shape: stale redemption hint lets a borrower redeem against an incorrectly ordered trove
- fix-shape: recompute ICR ordering before redemption execution
- detector-regex: SortedTroves|redeemCollateral|hint
- applicability heuristic: Liquity fork preserves SortedTroves redemption hints
- origin commit SHA: 0123456789abcdef
- source report reference: local-test
""".lstrip(),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--tag-dir",
                    str(tag_dir),
                    "--index-dir",
                    str(index_dir),
                    "--patterns-dir",
                    str(patterns_dir),
                    "--stage-dir",
                    str(stage_dir),
                    "--skip-verdict-tags",
                    "--skip-git-mining",
                    "--skip-corpus-mined",
                    "--skip-solodit-specs",
                    "--skip-findings-go",
                    "--skip-prior-audits",
                    "--dry-run",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summaries"]["solidity_fork_patterns"]["records_emitted"], 1)
            self.assertEqual(payload["staged_yaml"], 1)
            self.assertTrue(next(stage_dir.glob("*.yaml")).is_file())

    def test_default_solodit_spec_dirs_can_stage_non_primary_feeds_without_identity_collisions(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory(prefix="hackerman-refresh-solodit-feeds-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            index_dir = root / "index"
            stage_dir = root / "stage"
            primary_solodit = root / "drafts_solodit"
            primary_move = root / "drafts_solodit_move"
            rust_feed = root / "drafts_code4rena_rust"
            soroban_feed = root / "drafts_rust_soroban"
            solana_feed = root / "drafts_ottersec_solana"
            spec_dirs = (primary_solodit, primary_move, rust_feed, soroban_feed, solana_feed)
            tag_dir.mkdir()
            index_dir.mkdir()
            for spec_dir in spec_dirs:
                spec_dir.mkdir()
                (spec_dir / "shared-source.yaml").write_text(
                    f"""
id: shared-source
title: Shared non-primary feed source
severity: Medium
language: {"move" if spec_dir is primary_move else "rust"}
source: {spec_dir.name}
source_id: "SHARED-42"
bug_class: accounting
real_world_example: "Accounting drift in {spec_dir.name}."
suggested_remediation: "Namespace generated identities."
""".lstrip(),
                    encoding="utf-8",
                )
            (primary_solodit / "shared-source.yaml").write_text(
                """
name: stable-solodit-id
severity: MEDIUM
solodit_id: "22011"
wiki_title: Shared Solodit primary ID remains stable
wiki_description: "Primary Solodit specs keep their historical identity seed."
""".lstrip(),
                encoding="utf-8",
            )

            old_default_dirs = mod.DEFAULT_SOLODIT_SPEC_DIRS
            mod.DEFAULT_SOLODIT_SPEC_DIRS = spec_dirs
            try:
                args = mod.build_parser().parse_args(
                    [
                        "--tag-dir",
                        str(tag_dir),
                        "--index-dir",
                        str(index_dir),
                        "--stage-dir",
                        str(stage_dir),
                        "--skip-verdict-tags",
                        "--skip-git-mining",
                        "--skip-corpus-mined",
                        "--skip-solidity-fork-patterns",
                        "--skip-findings-go",
                        "--skip-prior-audits",
                        "--dry-run",
                    ]
                )
                payload = mod.refresh(args)
            finally:
                mod.DEFAULT_SOLODIT_SPEC_DIRS = old_default_dirs

            self.assertEqual(payload["summaries"]["solodit_specs"]["errors"], [])
            self.assertEqual(payload["summaries"]["solodit_specs"]["records_emitted"], 5)
            self.assertEqual(payload["staged_yaml"], 5)
            self.assertEqual(payload["identity_collisions"]["staged_duplicate_identities"], 0)
            self.assertEqual(payload["identity_collisions"]["live_identity_conflicts"], 0)
            rendered = "\n".join(path.read_text(encoding="utf-8") for path in sorted(stage_dir.glob("*.yaml")))
            self.assertRegex(rendered, r"record_id: solodit-spec:22011:[0-9a-f]{12}")
            self.assertRegex(rendered, r"record_id: solodit-spec:shared-42:[0-9a-f]{12}")
            for namespace in ("drafts_code4rena_rust", "drafts_rust_soroban", "drafts_ottersec_solana"):
                self.assertRegex(rendered, rf"record_id: solodit-spec:{namespace}:shared-42:[0-9a-f]{{12}}")

    def test_cli_apply_is_idempotent_for_same_content(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-refresh-apply-") as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            index_dir = root / "index"
            quality_out = root / "derived" / "record_quality.jsonl"
            cross_language_out = root / "derived" / "cross_language_analogues.jsonl"
            proof_hardening_out = root / "derived" / "proof_hardening.jsonl"
            tag_dir.mkdir()
            index_dir.mkdir()
            shutil.copy(VERDICT_FIXTURES / "legacy_v2_oracle.yaml", tag_dir / "legacy_v2_oracle.yaml")

            base_args = [
                sys.executable,
                str(TOOL),
                "--tag-dir",
                str(tag_dir),
                "--index-dir",
                str(index_dir),
                "--quality-out",
                str(quality_out),
                "--cross-language-out",
                str(cross_language_out),
                "--proof-hardening-out",
                str(proof_hardening_out),
                "--reports-dir",
                str(GIT_FIXTURES),
                "--corpus-dir",
                str(CORPUS_FIXTURES),
                "--skip-findings-go",
                "--skip-solodit-specs",
                "--skip-solidity-fork-patterns",
                "--workspace",
                str(PRIOR_FIXTURES / "alpha"),
            ]
            first = subprocess.run(base_args, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            first_payload = json.loads(first.stdout)
            self.assertGreater(first_payload["copied"], 0)
            self.assertTrue((index_dir / "by_attack_class.jsonl").is_file())
            self.assertTrue(quality_out.is_file())
            self.assertTrue(cross_language_out.is_file())
            self.assertTrue(proof_hardening_out.is_file())
            self.assertEqual(first_payload["quality_out"], str(quality_out.resolve()))
            self.assertEqual(first_payload["cross_language_out"], str(cross_language_out.resolve()))
            self.assertEqual(first_payload["proof_hardening_out"], str(proof_hardening_out.resolve()))
            self.assertGreater(first_payload["record_quality"]["records_scored"], 0)

            second = subprocess.run(base_args, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
            self.assertEqual(second.returncode, 0, second.stderr)
            second_payload = json.loads(second.stdout)
            self.assertEqual(second_payload["copied"], 0)
            self.assertGreater(second_payload["collisions"]["same_content_existing"], 0)
            self.assertEqual(second_payload["collisions"]["different_content_collisions"], 0)

    def test_cli_dry_run_can_stage_findings_go_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-refresh-findings-go-") as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            index_dir = root / "index"
            stage_dir = root / "stage"
            findings = root / "findings_go_fixture.jsonl"
            tag_dir.mkdir()
            index_dir.mkdir()
            findings.write_text(
                json.dumps(
                    {
                        "finding_id": "spark-lead1-2026-05-06",
                        "protocol": "Spark",
                        "language": "go",
                        "impact_tier": "critical",
                        "bug_class": "go.bitcoin.txid_equality_without_utxo_spend_check",
                        "github_ref": "github.com/buildonspark/spark@e8311d2",
                        "summary": "Chain-watcher accepts arbitrary txid proof without a UTXO spend check.",
                        "provenance": {
                            "source": "spark_engagement_back_feed",
                            "engagement_date": "2026-05-06",
                        },
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--tag-dir",
                    str(tag_dir),
                    "--index-dir",
                    str(index_dir),
                    "--stage-dir",
                    str(stage_dir),
                    "--findings-go-path",
                    str(findings),
                    "--skip-verdict-tags",
                    "--skip-git-mining",
                    "--skip-corpus-mined",
                    "--skip-solodit-specs",
                    "--skip-solidity-fork-patterns",
                    "--skip-prior-audits",
                    "--dry-run",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summaries"]["findings_go"]["records_emitted"], 1)
            self.assertEqual(payload["staged_yaml"], 1)
            self.assertTrue(next(stage_dir.glob("*.yaml")).is_file())

    def test_findings_to_invariants_wires_incident_derived_producer_canonical(self) -> None:
        """Guard for ITEM rank25-incident-invariant.

        The incident-derived-invariant-to-extracted producer feeds the same
        invariants_extracted.jsonl that evm-engine-harness-author /
        novel-vector-invariant-miner / batch-shape-cluster-predicates /
        semantic-predicate-gate / the vault MCP all consume, yet it was wired
        into no refresh stage. This asserts findings_to_invariants() now invokes
        it BEFORE the audit-ext lift when the derived dir is the canonical one.
        Fail-before: with the producer un-wired, no such command is issued.
        """
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            index_dir = Path(tmp) / "index"
            index_dir.mkdir()
            (index_dir / "by_attack_class.jsonl").write_text("{}\n")
            derived_dir = REPO_ROOT / "audit" / "corpus_tags" / "derived"

            calls: list[list[str]] = []

            def _fake_run(cmd: list[str]) -> dict[str, object]:
                calls.append(cmd)
                return {"status": "ok"}

            orig = mod._run_json_best_effort
            mod._run_json_best_effort = _fake_run  # type: ignore[assignment]
            try:
                summary = mod.findings_to_invariants(
                    index_dir=index_dir,
                    derived_dir=derived_dir,
                    repo_root=REPO_ROOT,
                    records_cap=1000,
                )
            finally:
                mod._run_json_best_effort = orig  # type: ignore[assignment]

            producer_calls = [
                c for c in calls
                if any("incident-derived-invariant-to-extracted.py" in str(part) for part in c)
            ]
            self.assertEqual(
                len(producer_calls), 1,
                f"incident-derived producer must be invoked exactly once; calls={calls}",
            )
            self.assertEqual(summary.get("incident_derived"), {"status": "ok"})

            # Ordering: the producer must run BEFORE the audit-ext lift so its rows
            # are picked up by the same lane-invariant-audit-ext pass.
            def _idx(needle: str) -> int:
                for i, c in enumerate(calls):
                    if any(needle in str(part) for part in c):
                        return i
                return -1

            self.assertLess(
                _idx("incident-derived-invariant-to-extracted.py"),
                _idx("lane-invariant-audit-ext.py"),
                "producer must run before the audit-ext lift",
            )

    def test_findings_to_invariants_skips_incident_producer_for_non_canonical_dir(self) -> None:
        """The producer only writes the canonical derived/invariants_extracted.jsonl,
        so a non-canonical (test/bespoke) derived dir must be skipped rather than
        scribbling the shared corpus."""
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            index_dir = Path(tmp) / "index"
            index_dir.mkdir()
            (index_dir / "by_attack_class.jsonl").write_text("{}\n")
            derived_dir = Path(tmp) / "derived"
            derived_dir.mkdir()

            calls: list[list[str]] = []

            def _fake_run(cmd: list[str]) -> dict[str, object]:
                calls.append(cmd)
                return {"status": "ok"}

            orig = mod._run_json_best_effort
            mod._run_json_best_effort = _fake_run  # type: ignore[assignment]
            try:
                summary = mod.findings_to_invariants(
                    index_dir=index_dir,
                    derived_dir=derived_dir,
                    repo_root=Path(tmp),
                    records_cap=1000,
                )
            finally:
                mod._run_json_best_effort = orig  # type: ignore[assignment]

            producer_calls = [
                c for c in calls
                if any("incident-derived-invariant-to-extracted.py" in str(part) for part in c)
            ]
            self.assertEqual(producer_calls, [], "producer must NOT run for a non-canonical derived dir")
            self.assertEqual(summary["incident_derived"]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
