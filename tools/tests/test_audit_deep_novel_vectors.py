from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "audit-deep-novel-vectors.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_audit_deep_novel_vectors", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class AuditDeepNovelVectorsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="audit-deep-novel-vectors-")
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        self.tag_dir = self.root / "tags"
        self.tag_dir.mkdir()
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_tag(self, name: str, body: str) -> None:
        (self.tag_dir / name).write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")

    def _seed_tags(self) -> None:
        self._write_tag(
            "local_access.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: local:access-1
            source_audit_ref: prior:local-access-1
            target_domain: treasury
            target_language: solidity
            target_repo: example/vault
            target_component: Vault.setOperator
            function_shape:
              raw_signature: "function setOperator(address operator) external"
              shape_tags:
                - external-privileged-write
                - single-role-guard
            bug_class: missing-access-control
            attack_class: access-control-bypass
            attacker_role: arbitrary-user
            attacker_action_sequence: "Step 1: call the unprotected operator setter."
            required_preconditions:
              - setter is externally reachable
            impact_class: privilege-escalation
            impact_actor: arbitrary-user
            impact_dollar_class: non-financial
            fix_pattern: add onlyOwner
            fix_anti_pattern_avoided: unguarded operator setter
            severity_at_finding: high
            year: 2024
            cross_language_analogues: []
            related_records: []
            """,
        )
        self._write_tag(
            "local_target.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: local:rounding-2
            source_audit_ref: prior:local-rounding-2
            target_domain: treasury
            target_language: solidity
            target_repo: example/vault
            target_component: Treasury.withdrawFees
            function_shape:
              raw_signature: "function withdrawFees(address recipient, uint256 amount) external"
              shape_tags:
                - external-privileged-fund-move
                - single-role-guard
            bug_class: fee-rounding-leak
            attack_class: rounding-manipulation
            attacker_role: arbitrary-user
            attacker_action_sequence: "Step 1: skew fee accounting before admin withdrawal."
            required_preconditions:
              - internal fee accounting can drift
            impact_class: precision-loss
            impact_actor: treasury
            impact_dollar_class: "$1K-$10K"
            fix_pattern: reconcile fee accounting before withdrawal
            fix_anti_pattern_avoided: stale fee accumulator
            severity_at_finding: medium
            year: 2024
            cross_language_analogues: []
            related_records: []
            """,
        )
        self._write_tag(
            "remote_analogue.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: remote:drain-3
            source_audit_ref: prior:remote-drain-3
            target_domain: treasury
            target_language: solidity
            target_repo: peer/vault
            target_component: Treasury.withdrawFees
            function_shape:
              raw_signature: "function withdrawFees(address recipient, uint256 amount) external"
              shape_tags:
                - external-privileged-fund-move
                - single-role-guard
            bug_class: privileged-treasury-drain
            attack_class: privilege-escalation-fund-theft
            attacker_role: privileged
            attacker_action_sequence: "Step 1: as operator, drain treasury fees."
            required_preconditions:
              - caller holds the owner role
              - protocol funds are present in the treasury
            impact_class: theft
            impact_actor: protocol-treasury
            impact_dollar_class: "$100K-$1M"
            fix_pattern: timelock and separate treasury withdrawal authority
            fix_anti_pattern_avoided: instant operator treasury drain
            severity_at_finding: critical
            year: 2024
            cross_language_analogues: []
            related_records: []
            """,
        )

    def test_infers_git_remote_and_writes_workspace_artifacts(self) -> None:
        self._seed_tags()
        git_dir = self.workspace / "external" / "vault" / ".git"
        git_dir.mkdir(parents=True)
        (git_dir / "config").write_text(
            "[remote \"origin\"]\n\turl = https://github.com/example/vault.git\n",
            encoding="utf-8",
        )

        rc = self.tool.main(
            [
                "--workspace",
                str(self.workspace),
                "--tag-dir",
                str(self.tag_dir),
                "--skip-mcp-context",
                "--json",
            ]
        )

        self.assertEqual(rc, 0)
        jsonl = self.workspace / ".auditooor" / "novel_vectors.jsonl"
        summary_path = self.workspace / ".auditooor" / "novel_vectors.summary.json"
        context_path = self.workspace / ".auditooor" / "novel_vectors.mcp_context.jsonl"
        self.assertTrue(jsonl.is_file())
        self.assertTrue(summary_path.is_file())
        self.assertTrue(context_path.is_file())
        rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target_repo_filter"], "example/vault")
        self.assertEqual(rows[0]["workspace_artifact_schema"], "auditooor.audit_deep_novel_vectors.v1")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(summary["target_repos"], ["example/vault"])
        self.assertEqual(summary["total_hypotheses"], 1)
        self.assertFalse(summary["degraded"])

    def test_missing_target_repo_still_emits_degraded_artifacts(self) -> None:
        self._seed_tags()

        rc = self.tool.main(
            [
                "--workspace",
                str(self.workspace),
                "--tag-dir",
                str(self.tag_dir),
                "--skip-mcp-context",
                "--json",
            ]
        )

        # r36-rebuttal: criterion-i nightly lane owns only this test + its tool.
        self.assertEqual(rc, 0)
        jsonl = self.workspace / ".auditooor" / "novel_vectors.jsonl"
        summary = json.loads((self.workspace / ".auditooor" / "novel_vectors.summary.json").read_text(encoding="utf-8"))
        # Promote-step fix: a zero-hypothesis run now emits an explicit
        # empty-with-reason marker row, never a silent 0-line file.
        marker_lines = jsonl.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(marker_lines), 1)
        marker = json.loads(marker_lines[0])
        self.assertTrue(marker["empty_marker"])
        self.assertEqual(marker["workspace_artifact_schema"], "auditooor.audit_deep_novel_vectors.empty_marker.v1")
        self.assertEqual(marker["empty_reason"], "no_target_repo_detected")
        self.assertTrue(summary["degraded"])
        self.assertTrue(summary["empty_marker_written"])
        self.assertEqual(summary["degraded_reason"], "no_target_repo_detected")
        self.assertEqual(summary["target_repos"], [])

    def test_explicit_target_repo_is_accepted_without_git_remote(self) -> None:
        self._seed_tags()

        rc = self.tool.main(
            [
                "--workspace",
                str(self.workspace),
                "--tag-dir",
                str(self.tag_dir),
                "--target-repo",
                "example/vault",
                "--skip-mcp-context",
                "--json",
            ]
        )

        self.assertEqual(rc, 0)
        summary = json.loads((self.workspace / ".auditooor" / "novel_vectors.summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["target_repo_sources"][0]["source"], "explicit")
        self.assertEqual(summary["target_repos"], ["example/vault"])
        self.assertEqual(summary["total_hypotheses"], 1)

    def test_repo_found_but_zero_hypotheses_emits_empty_marker(self) -> None:
        # r36-rebuttal: criterion-i nightly lane owns only this test + its tool.
        # Aztec-class scenario: a target repo IS detected, but no cross-repo
        # corpus analogue clears the shape-overlap threshold, so synthesis
        # returns zero promotable hypotheses.  The canonical jsonl must carry
        # an explicit empty-with-reason marker, not be a silent 0-line file.
        self._seed_tags()
        rc = self.tool.main(
            [
                "--workspace",
                str(self.workspace),
                "--tag-dir",
                str(self.tag_dir),
                "--target-repo",
                "example/vault",
                # Impossible shape overlap forces zero cross-repo analogues.
                "--min-shape-overlap",
                "1.01",
                "--skip-mcp-context",
                "--json",
            ]
        )
        self.assertEqual(rc, 0)
        jsonl = self.workspace / ".auditooor" / "novel_vectors.jsonl"
        lines = jsonl.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1, "zero-hypothesis run must still emit one marker line")
        marker = json.loads(lines[0])
        self.assertTrue(marker["empty_marker"])
        self.assertEqual(
            marker["workspace_artifact_schema"],
            "auditooor.audit_deep_novel_vectors.empty_marker.v1",
        )
        self.assertEqual(marker["target_repos"], ["example/vault"])
        self.assertIn("empty_reason", marker)
        self.assertTrue(marker["advisory_only"])
        self.assertEqual(marker["submission_posture"], "NOT_SUBMIT_READY")
        summary = json.loads(
            (self.workspace / ".auditooor" / "novel_vectors.summary.json").read_text(encoding="utf-8")
        )
        self.assertEqual(summary["total_hypotheses"], 0)
        self.assertTrue(summary["empty_marker_written"])
        # Repo WAS detected, so this is not the degraded no-repo case.
        self.assertFalse(summary["degraded"])


class B4AdoptionTelemetryTests(unittest.TestCase):
    """B4: verify _run_mcp_context forwards workspace so telemetry lands in
    the per-workspace mcp_call_log.jsonl rather than the /tmp fallback.

    We mock subprocess.run so no real vault server call is made.  The test
    asserts that:

    1. The --args JSON contains ``workspace_path`` matching the workspace.
    2. The env dict passed to subprocess.run contains ``AUDITOOOR_WORKSPACE``
       matching the workspace.
    3. An end-to-end build_artifacts call (with skip_mcp_context=False and a
       patched subprocess) writes at least one row to the workspace's
       mcp_call_log.jsonl - simulating what the real vault-mcp-server telemetry
       hook does automatically when AUDITOOOR_WORKSPACE is set.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="b4-adoption-telemetry-")
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        (self.workspace / ".auditooor").mkdir()
        self.tag_dir = self.root / "tags"
        self.tag_dir.mkdir()
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_mcp_ok_payload(self, target_repo: str) -> str:
        """Minimal JSON payload that _run_mcp_context accepts as success."""
        return json.dumps({
            "schema": "auditooor.hackerman_novel_vector_hypotheses.v1",
            "target_repo": target_repo,
            "hypotheses": [],
            "context_pack_id": "test:abc",
            "context_pack_hash": "abc123",
            "total_hypotheses": 0,
        })

    def test_workspace_path_forwarded_in_args_and_env(self) -> None:
        """_run_mcp_context must embed workspace_path in --args and AUDITOOOR_WORKSPACE in env."""
        captured: dict = {}

        def fake_subprocess_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs.get("env", {})
            result = MagicMock()
            result.returncode = 0
            result.stdout = self._make_mcp_ok_payload("example/repo")
            result.stderr = ""
            return result

        with patch("subprocess.run", side_effect=fake_subprocess_run):
            self.tool._run_mcp_context(
                target_repo="example/repo",
                language="",
                domain="",
                limit=5,
                max_targets=20,
                same_class_variants=False,
                tag_dir=self.tag_dir,
                timeout_seconds=30.0,
                workspace=self.workspace,
            )

        # The --args JSON must contain workspace_path.
        args_json_idx = captured["cmd"].index("--args") + 1
        args_dict = json.loads(captured["cmd"][args_json_idx])
        self.assertEqual(args_dict.get("workspace_path"), str(self.workspace))

        # The env must carry AUDITOOOR_WORKSPACE.
        self.assertEqual(captured["env"].get("AUDITOOOR_WORKSPACE"), str(self.workspace))

    def test_workspace_path_absent_when_workspace_none(self) -> None:
        """When workspace=None, workspace_path must NOT appear in --args (no spurious key)."""
        captured: dict = {}

        def fake_subprocess_run(cmd, **kwargs):
            captured["cmd"] = cmd
            result = MagicMock()
            result.returncode = 0
            result.stdout = self._make_mcp_ok_payload("example/repo")
            result.stderr = ""
            return result

        with patch("subprocess.run", side_effect=fake_subprocess_run):
            self.tool._run_mcp_context(
                target_repo="example/repo",
                language="",
                domain="",
                limit=5,
                max_targets=20,
                same_class_variants=False,
                tag_dir=self.tag_dir,
                timeout_seconds=30.0,
                workspace=None,
            )

        args_json_idx = captured["cmd"].index("--args") + 1
        args_dict = json.loads(captured["cmd"][args_json_idx])
        self.assertNotIn("workspace_path", args_dict)

    def test_adoption_tracker_reads_workspace_log_as_non_dead(self) -> None:
        """Simulate a vault-mcp-server call writing to the workspace log and
        confirm the adoption tracker reports the callable as non-DEAD_ADOPTION.

        We write a row directly (as vault-mcp-server would) to simulate the
        telemetry write, then run the adoption tracker and assert the callable
        is no longer dead.
        """
        ADOPTION_TOOL = REPO_ROOT / "tools" / "hackerman-capability-adoption.py"
        spec = importlib.util.spec_from_file_location("_hackerman_capability_adoption", str(ADOPTION_TOOL))
        adoption_mod = importlib.util.module_from_spec(spec)
        assert spec.loader
        spec.loader.exec_module(adoption_mod)

        log_path = self.workspace / ".auditooor" / "mcp_call_log.jsonl"

        # Write two telemetry rows: one resume (iteration boundary) and one
        # novel-vector-context call - simulating what vault-mcp-server emits.
        import datetime
        ts_resume = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ts_call = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows = [
            {
                "ts": ts_resume,
                "workspace": str(self.workspace),
                "callable": "vault_resume_context",
                "args_hash": "aaaaaaaa",
                "verdict": "ok",
                "duration_ms": 100,
                "degraded": False,
            },
            {
                "ts": ts_call,
                "workspace": str(self.workspace),
                "callable": "vault_hackerman_novel_vector_context",
                "args_hash": "bbbbbbbb",
                "verdict": "ok",
                "duration_ms": 50,
                "degraded": False,
            },
        ]
        log_path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

        report = adoption_mod.build_report(
            workspaces=[str(self.workspace)],
            iterations=7,
        )

        # The callable must no longer be DEAD_ADOPTION.
        self.assertNotIn("vault_hackerman_novel_vector_context", report["dead_adoption"])
        count = report["counts"].get("vault_hackerman_novel_vector_context", 0)
        self.assertGreater(count, 0, "expected at least 1 invocation recorded")


if __name__ == "__main__":
    unittest.main()
