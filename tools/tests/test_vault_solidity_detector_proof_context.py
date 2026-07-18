from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
EXPECTED_SCHEMA = "auditooor.vault_solidity_detector_proof_context.v1"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_solidity_detector_proof_context",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _action_graph(detector_slug: str = "withdraw-reentrancy-no-guard") -> dict[str, object]:
    return {
        "schema": "auditooor.vault_detector_action_graph_context.v1",
        "advisory_only": True,
        "submission_posture": "NOT_SUBMIT_READY",
        "detector_hit": {
            "detector_slug": detector_slug,
            "file_path": "src/Vault.sol:42",
            "severity": "HIGH",
            "snippet": "withdraw calls receiver before debt accounting is finalized",
        },
        "ranked_attack_classes": [
            {"attack_class": "reentrancy", "score": 97, "confidence": "high"}
        ],
        "action_graph": {
            "nodes": [
                {"id": "goal", "kind": "attacker_goal", "title": "reenter withdraw"},
                {"id": "impact", "kind": "impact_probe", "title": "drain more assets than shares"},
            ],
            "edges": [{"from": "goal", "to": "impact", "relation": "leads_to"}],
        },
        "proof_obligations": [
            {
                "id": "poc-impact",
                "kind": "foundry_poc_execution",
                "status": "open",
                "title": "execute Foundry PoC against project source",
            }
        ],
        "chain_candidates": [
            {
                "chain_id": "CHAIN-001",
                "status": "candidate_not_submit_ready",
                "source_refs": ["workspace:src/Vault.sol:42"],
            }
        ],
    }


def _proof_queue(*rows: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "auditooor.detector_proof_gap_queue.v1",
        "sections": {
            "fixture_needed": {"rows": list(rows)},
            "proof_verified": {"rows": []},
        },
        "full_throttle": {"rows": list(rows)},
    }


def _canonical_proof_obligation_queue(detector_slug: str) -> dict[str, object]:
    return {
        "schema": "auditooor.proof_obligation_queue.v1",
        "advisory_only": True,
        "status": "ready",
        "summary": {"task_count": 1, "detector_action_graph_tasks": 1},
        "tasks": [
            {
                "task_id": "POQ-001",
                "detector_action_graph_obligation": "P-001",
                "obligation_kind": "foundry_poc_execution",
                "detector": detector_slug,
                "proof_needed": "Execute Foundry PoC against project source",
                "blocker": "open detector action graph obligation `foundry_poc_execution`",
                "source_refs": ["<workspace>/src/Vault.sol:42"],
                "file_hints": ["src/Vault.sol:42"],
                "source_ref": "<workspace>/.auditooor/detector_action_graphs/hit_000_withdraw.json",
                "advisory_only": True,
            }
        ],
    }


def _proof_queue_freshness_marker(*, stale: bool = False, status: str = "fresh_bridge_completed") -> dict[str, object]:
    return {
        "schema": "auditooor.proof_queue_freshness_marker.v1",
        "workspace": "<workspace>",
        "advisory_only": True,
        "status": status,
        "stale": stale,
        "mode": "mark-stale" if stale else "mark-fresh",
        "reason": "bridge failed" if stale else "bridge completed",
        "bridge_rc": 2 if stale else 0,
        "generated_at_utc": "2026-05-13T10:00:00Z",
        "proof_queue": {
            "path": "<workspace>/.auditooor/proof_obligation_queue.json",
            "exists": True,
            "json_valid": True,
            "schema": "auditooor.proof_obligation_queue.v1",
            "status": "ready",
            "context_pack_id": "proof-queue:test",
            "task_count": 1,
            "generated_at_utc": "2026-05-13T09:59:00Z",
            "mtime_utc": "2026-05-13T09:59:00Z",
        },
    }


def _solidity_queue_row(detector_slug: str = "withdraw-reentrancy-no-guard") -> dict[str, object]:
    return {
        "queue_id": detector_slug,
        "scanner_id": detector_slug,
        "backend": "solidity",
        "language": "solidity",
        "section": "fixture_needed",
        "proof_status": "detector_without_fixture_pair",
        "wiring_status": "generated_no_fixture",
        "source_paths": [
            f"detectors/wave20/{detector_slug}.py",
            "src/Vault.sol",
        ],
        "blockers": ["runtime_or_smoke_proof_missing"],
        "suggested_test_command": "JOBS=1 forge test --match-test testWithdrawReentrancy",
        "claim_guard": "No validity claim: fixture/proof evidence is missing.",
    }


def _rust_queue_row() -> dict[str, object]:
    return {
        "queue_id": "rust-cache-stale",
        "scanner_id": "rust-cache-stale",
        "backend": "rust",
        "language": "rust",
        "section": "rust_lift_needed",
        "proof_status": "source_shape_only",
        "source_paths": ["detectors/rust_wave1/rust-cache-stale.py"],
        "blockers": ["rust_runtime_semantics_unverified"],
    }


def _proved_manifest(workspace: Path, detector_slug: str) -> dict[str, object]:
    return {
        "schema_version": "auditooor.poc_execution_manifest.v1",
        "candidate_id": detector_slug,
        "workspace": str(workspace),
        "commands_attempted": [
            {
                "command": "forge test --match-test testWithdrawReentrancy",
                "cwd": str(workspace),
                "exit_code": 0,
                "status": "pass",
                "stdout_path": str(
                    workspace / "poc_execution" / detector_slug / "command_001.stdout.log"
                ),
            }
        ],
        "artifact_paths": [
            str(workspace / "poc_execution" / detector_slug / "command_001.stdout.log")
        ],
        "final_result": "proved",
        "impact_assertion": "exploit_impact",
        "evidence_class": "executed_with_manifest",
    }


def _fixture_smoke(detector_slug: str, *, status: str = "smoke_pass", positive_hits: int = 1, clean_hits: int = 0) -> dict[str, object]:
    pattern = detector_slug.replace("_", "-")
    return {
        "schema": "auditooor.canonical_detector_fixture_smoke.v1",
        "pattern": pattern,
        "detector_slug": detector_slug,
        "detector_path": f"detectors/wave17/{detector_slug}.py",
        "fixture_id": detector_slug,
        "status": status,
        "submission_posture": "NOT_SUBMIT_READY",
        "coverage_claim": "detector_fixture_smoke_only",
        "promotion_allowed": False,
        "positive_fixture": f"detectors/fixtures/{detector_slug}/positive.sol",
        "clean_fixture": f"detectors/fixtures/{detector_slug}/clean.sol",
        "positive_hits": positive_hits,
        "clean_hits": clean_hits,
        "positive_command": (
            "AUDITOOOR_FIXTURE_SMOKE_MODE=1 python3 detectors/run_custom.py "
            f"detectors/fixtures/{detector_slug}/positive.sol {pattern}"
        ),
        "clean_command": (
            "AUDITOOOR_FIXTURE_SMOKE_MODE=1 python3 detectors/run_custom.py "
            f"detectors/fixtures/{detector_slug}/clean.sol {pattern}"
        ),
    }


class VaultSolidityDetectorProofContextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-solidity-detector-proof-context-")
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.vault_dir = self.base / "vault"
        self.ws = self.base / "workspace"
        self.repo.mkdir()
        self.vault_dir.mkdir()
        self.ws.mkdir()
        _write(
            self.repo / "templates" / "poc_isolated_test.t.sol",
            "contract PocTemplate { function testExploitImpact() public {} }\n",
        )
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(self.vault_dir, repo_root=self.repo)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_inputs(self, *, include_rust: bool = False) -> str:
        detector_slug = "withdraw-reentrancy-no-guard"
        _write_json(
            self.ws / ".auditooor" / "detector_action_graph_context.json",
            _action_graph(detector_slug),
        )
        rows = [_solidity_queue_row(detector_slug)]
        if include_rust:
            rows.append(_rust_queue_row())
        _write_json(
            self.ws / ".auditooor" / "detector_proof_gap_queue.json",
            _proof_queue(*rows),
        )
        return detector_slug

    def _write_fixture_smoke(self, detector_slug: str, payload: dict[str, object] | None = None) -> None:
        fixture_dir = self.repo / "detectors" / "fixtures" / detector_slug
        _write(fixture_dir / "positive.sol", "contract PositiveFixture {}\n")
        _write(fixture_dir / "clean.sol", "contract CleanFixture {}\n")
        _write_json(fixture_dir / "smoke.json", payload or _fixture_smoke(detector_slug))

    def _write_canonical_task_inputs(self, detector_slug: str = "withdraw-reentrancy-no-guard") -> None:
        graph_path = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
        _write_json(graph_path, _action_graph(detector_slug))
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_withdraw.json"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            _canonical_proof_obligation_queue(detector_slug),
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.freshness.json",
            _proof_queue_freshness_marker(),
        )

    def test_missing_workspace_or_artifacts_degrades_fail_closed(self) -> None:
        self.assertTrue(
            hasattr(self.vault, "vault_solidity_detector_proof_context"),
            "VaultQuery must expose vault_solidity_detector_proof_context",
        )

        missing_workspace = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.base / "missing-workspace"),
        )
        self.assertEqual(missing_workspace["schema"], EXPECTED_SCHEMA)
        self.assertTrue(missing_workspace["degraded"])
        self.assertTrue(missing_workspace["advisory_only"])
        self.assertEqual(missing_workspace["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(missing_workspace["promotion_allowed"])
        self.assertEqual(missing_workspace["rows"], [])

        missing_artifacts = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
        )
        self.assertEqual(missing_artifacts["schema"], EXPECTED_SCHEMA)
        self.assertTrue(missing_artifacts["degraded"])
        self.assertTrue(missing_artifacts["advisory_only"])
        self.assertEqual(missing_artifacts["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(missing_artifacts["promotion_allowed"])
        self.assertEqual(missing_artifacts["rows"], [])
        self.assertIn("detector", missing_artifacts.get("degraded_reason", ""))

        payload = json.dumps(missing_artifacts, sort_keys=True)
        self.assertNotIn(str(self.base), payload)
        self.assertNotIn("/private/", payload)
        self.assertNotIn("/Users/", payload)

    def test_solidity_action_graph_queue_and_template_emit_unsafe_preview_row_without_marker(self) -> None:
        detector_slug = self._write_inputs()

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
            limit=4,
        )

        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertEqual(result["kind"], "solidity_detector_proof_context")
        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(result["promotion_allowed"])
        self.assertEqual(result["summary"]["rows_returned"], 1)
        self.assertEqual(result["summary"]["ready_for_foundry_poc_count"], 0)
        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 0)
        self.assertTrue(result["privacy_guards"]["workspace_relative_refs_only"])
        self.assertTrue(result["privacy_guards"]["absolute_local_paths_blocked"])

        row = result["rows"][0]
        self.assertEqual(row["detector_slug"], detector_slug)
        self.assertEqual(row["language"], "solidity")
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(row["proof_readiness"], "blocked")
        self.assertEqual(row["underlying_proof_readiness"], "ready_for_foundry_poc")
        self.assertIn("blocked", row["status"])
        self.assertIn("missing_execution_manifest", row["blockers"])
        self.assertEqual(row["execution_evidence"], "missing")
        self.assertEqual(row["fixture_smoke_status"], "missing")
        self.assertIn("fixture_smoke_evidence_missing_or_invalid", row["blockers"])
        self.assertIn("poc_isolated_test.t.sol", row["template_ref"])
        self.assertIn("forge test", row["next_command"])
        self.assertEqual(row["action_graph"]["detector_hit"]["file_path"], "src/Vault.sol:42")
        self.assertFalse(row["safe_to_treat_as_current"])
        self.assertEqual(row["artifact_freshness_status"], "missing_freshness_marker")
        self.assertTrue(row["derived_from_stale_artifact"])
        self.assertIn("proof_queue_freshness_not_current", row["blockers"])
        self.assertFalse(
            result["freshness"]["proof_obligation_queue_marker"]["safe_to_treat_as_current"]
        )
        self.assertEqual(
            result["freshness"]["proof_obligation_queue_marker"]["status"],
            "missing_freshness_marker",
        )

        payload = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(self.base), payload)
        self.assertNotIn("/private/", payload)
        self.assertNotIn("/Users/", payload)

    def test_fresh_proof_queue_marker_marks_rows_current_without_submission_readiness(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        graph_path = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
        _write_json(graph_path, _action_graph(detector_slug))
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_withdraw.json"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            _canonical_proof_obligation_queue(detector_slug),
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.freshness.json",
            _proof_queue_freshness_marker(),
        )
        self._write_fixture_smoke(detector_slug.replace("-", "_"))

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertTrue(result["freshness"]["detector_artifacts"]["safe_to_treat_as_current"])
        marker = result["freshness"]["proof_obligation_queue_marker"]
        self.assertEqual(marker["status"], "fresh_bridge_completed")
        self.assertFalse(marker["stale"])
        self.assertTrue(marker["safe_to_treat_as_current"])
        self.assertEqual(marker["marker_ref"], ".auditooor/proof_obligation_queue.freshness.json")
        self.assertEqual(marker["queue_ref"], ".auditooor/proof_obligation_queue.json")
        self.assertTrue(marker["queue_ref_matches_loaded_queue"])
        row = result["rows"][0]
        self.assertTrue(row["safe_to_treat_as_current"])
        self.assertEqual(row["artifact_freshness_status"], "fresh_bridge_completed")
        self.assertFalse(row["derived_from_stale_artifact"])
        self.assertEqual(row["fixture_smoke_status"], "fixture_smoke_passed")
        self.assertEqual(row["fixture_smoke"]["positive_hits"], 1)
        self.assertEqual(row["fixture_smoke"]["clean_hits"], 0)
        self.assertEqual(row["fixture_smoke"]["evidence_class"], "fixture_smoke_only")
        self.assertFalse(row["fixture_smoke"]["promotion_allowed"])
        self.assertEqual(result["summary"]["fixture_smoke_passed_count"], 1)
        self.assertEqual(result["summary"]["fixture_smoke_counts"]["fixture_smoke_passed"], 1)
        self.assertNotIn("proof_queue_freshness_not_current", row["blockers"])
        self.assertNotIn("fixture_smoke_evidence_missing_or_invalid", row["blockers"])
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(row["promotion_allowed"])

    def test_invalid_fixture_smoke_is_blocking_advisory_metadata(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        graph_path = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
        _write_json(graph_path, _action_graph(detector_slug))
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_withdraw.json"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            _canonical_proof_obligation_queue(detector_slug),
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.freshness.json",
            _proof_queue_freshness_marker(),
        )
        self._write_fixture_smoke(
            detector_slug.replace("-", "_"),
            _fixture_smoke(detector_slug.replace("-", "_"), clean_hits=1),
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        row = result["rows"][0]
        self.assertEqual(row["fixture_smoke_status"], "fixture_smoke_not_valid")
        self.assertIn("fixture_smoke_clean_hits_nonzero", row["fixture_smoke"]["blockers"])
        self.assertIn("fixture_smoke_evidence_missing_or_invalid", row["blockers"])
        self.assertEqual(result["summary"]["fixture_smoke_passed_count"], 0)
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(row["promotion_allowed"])

    def test_fixture_smoke_explicit_detector_mismatch_is_blocking(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        graph_path = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
        _write_json(graph_path, _action_graph(detector_slug))
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_withdraw.json"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            _canonical_proof_obligation_queue(detector_slug),
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.freshness.json",
            _proof_queue_freshness_marker(),
        )
        smoke = _fixture_smoke(detector_slug.replace("-", "_"))
        smoke["detector_slug"] = "totally_different_detector"
        smoke["pattern"] = "totally-different-detector"
        smoke["detector_path"] = "detectors/wave17/totally_different_detector.py"
        self._write_fixture_smoke(detector_slug.replace("-", "_"), smoke)

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        row = result["rows"][0]
        self.assertEqual(row["fixture_smoke_status"], "fixture_smoke_not_valid")
        self.assertIn("fixture_smoke_detector_binding_mismatch", "; ".join(row["fixture_smoke"]["blockers"]))
        self.assertIn("fixture_smoke_evidence_missing_or_invalid", row["blockers"])
        self.assertEqual(result["summary"]["fixture_smoke_passed_count"], 0)

    def test_stale_proof_queue_marker_surfaces_routing_blocker(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        graph_path = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
        _write_json(graph_path, _action_graph(detector_slug))
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_withdraw.json"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            _canonical_proof_obligation_queue(detector_slug),
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.freshness.json",
            _proof_queue_freshness_marker(stale=True, status="stale_existing_proof_queue"),
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        marker = result["freshness"]["proof_obligation_queue_marker"]
        self.assertEqual(marker["status"], "stale_existing_proof_queue")
        self.assertTrue(marker["stale"])
        self.assertFalse(marker["safe_to_treat_as_current"])
        self.assertIn("proof_queue_marker_stale", marker["warnings"])
        self.assertFalse(result["freshness"]["detector_artifacts"]["safe_to_treat_as_current"])
        row = result["rows"][0]
        self.assertFalse(row["safe_to_treat_as_current"])
        self.assertEqual(row["artifact_freshness_status"], "stale_existing_proof_queue")
        self.assertTrue(row["derived_from_stale_artifact"])
        self.assertIn("proof_queue_freshness_not_current", row["blockers"])
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(row["promotion_allowed"])

    def test_proved_execution_manifest_marks_evidence_but_remains_advisory_not_submit_ready(self) -> None:
        detector_slug = self._write_inputs()
        _write_json(
            self.ws / "poc_execution" / detector_slug / "execution_manifest.json",
            _proved_manifest(self.ws, detector_slug),
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(result["promotion_allowed"])
        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 1)

        row = result["rows"][0]
        self.assertEqual(row["execution_evidence"], "proved_impact_evidence")
        self.assertEqual(row["execution_manifest"]["final_result"], "proved")
        self.assertEqual(row["execution_manifest"]["impact_assertion"], "exploit_impact")
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertTrue(row["advisory_only"])
        self.assertFalse(row["promotion_allowed"])
        self.assertIn("advisory_not_submission_ready", row["blockers"])

        payload = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(self.base), payload)
        self.assertNotIn("/private/", payload)
        self.assertNotIn("/Users/", payload)

    def test_execution_manifest_join_uses_proof_task_and_detector_metadata_before_candidate_id(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        graph_path = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
        _write_json(graph_path, _action_graph(detector_slug))
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_withdraw.json"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            _canonical_proof_obligation_queue(detector_slug),
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.freshness.json",
            _proof_queue_freshness_marker(),
        )
        manifest = _proved_manifest(self.ws, "manual-rerun-001")
        manifest.update(
            {
                "candidate_id": "manual-rerun-001",
                "proof_task_id": "POQ-001",
                "detector_slug": detector_slug,
                "detector_obligation": "P-001",
                "detector_action_graph": ".auditooor/detector_action_graphs/hit_000_withdraw.json",
            }
        )
        _write_json(
            self.ws / "poc_execution" / "manual-rerun-001" / "execution_manifest.json",
            manifest,
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertEqual(result["summary"]["rows_returned"], 1)
        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 1)
        row = result["rows"][0]
        self.assertEqual(row["detector_slug"], detector_slug)
        self.assertEqual(row["proof_readiness"], "proved_impact_evidence")
        self.assertEqual(row["execution_evidence"], "proved_impact_evidence")
        self.assertEqual(row["poc_execution_record_status"], "present")
        self.assertEqual(row["execution_manifest"]["candidate_id"], "manual-rerun-001")
        self.assertEqual(row["execution_manifest"]["proof_task_id"], "POQ-001")
        self.assertEqual(row["execution_manifest"]["detector_slug"], detector_slug)
        self.assertEqual(row["execution_manifest"]["detector_obligation"], "P-001")
        self.assertEqual(
            row["execution_manifest"]["detector_action_graph"],
            ".auditooor/detector_action_graphs/hit_000_withdraw.json",
        )
        payload = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(self.base), payload)
        self.assertNotIn("/private/", payload)
        self.assertNotIn("/Users/", payload)

    def test_execution_manifest_matching_task_id_but_wrong_detector_is_blocked(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        self._write_canonical_task_inputs(detector_slug)
        manifest = _proved_manifest(self.ws, "manual-rerun-wrong-detector")
        manifest.update(
            {
                "candidate_id": "manual-rerun-wrong-detector",
                "proof_task_id": "POQ-001",
                "detector_slug": "different-detector",
                "detector_obligation": "P-001",
                "detector_action_graph": ".auditooor/detector_action_graphs/hit_000_withdraw.json",
            }
        )
        _write_json(
            self.ws / "poc_execution" / "manual-rerun-wrong-detector" / "execution_manifest.json",
            manifest,
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 0)
        self.assertEqual(result["summary"]["execution_manifest_metadata_conflict_count"], 1)
        row = result["rows"][0]
        self.assertEqual(row["proof_readiness"], "blocked")
        self.assertEqual(row["execution_evidence"], "execution_manifest_metadata_conflict")
        self.assertEqual(row["poc_execution_record_status"], "metadata_conflict")
        self.assertIn("execution_manifest_detector_slug_conflict", row["blockers"])
        self.assertFalse(row["promotion_allowed"])

    def test_execution_manifest_matching_obligation_but_wrong_proof_task_is_blocked(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        self._write_canonical_task_inputs(detector_slug)
        queue_path = self.ws / ".auditooor" / "proof_obligation_queue.json"
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
        queue["tasks"][0]["task_id"] = "POQ-002"
        queue_path.write_text(json.dumps(queue), encoding="utf-8")
        manifest = _proved_manifest(self.ws, "manual-rerun-wrong-task")
        manifest.update(
            {
                "candidate_id": "manual-rerun-wrong-task",
                "proof_task_id": "POQ-001",
                "detector_slug": detector_slug,
                "detector_obligation": "P-001",
                "detector_action_graph": ".auditooor/detector_action_graphs/hit_000_withdraw.json",
            }
        )
        _write_json(
            self.ws / "poc_execution" / "manual-rerun-wrong-task" / "execution_manifest.json",
            manifest,
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 0)
        self.assertEqual(result["summary"]["execution_manifest_metadata_conflict_count"], 1)
        row = result["rows"][0]
        self.assertEqual(row["proof_readiness"], "blocked")
        self.assertEqual(row["execution_evidence"], "execution_manifest_metadata_conflict")
        self.assertIn("execution_manifest_proof_task_id_conflict", row["blockers"])
        self.assertFalse(row["promotion_allowed"])

    def test_execution_manifest_with_stale_action_graph_ref_is_blocked(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        self._write_canonical_task_inputs(detector_slug)
        manifest = _proved_manifest(self.ws, "manual-rerun-old-graph")
        manifest.update(
            {
                "candidate_id": "manual-rerun-old-graph",
                "proof_task_id": "POQ-001",
                "detector_slug": detector_slug,
                "detector_obligation": "P-001",
                "detector_action_graph": ".auditooor/detector_action_graphs/hit_old.json",
            }
        )
        _write_json(
            self.ws / "poc_execution" / "manual-rerun-old-graph" / "execution_manifest.json",
            manifest,
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 0)
        row = result["rows"][0]
        self.assertEqual(row["proof_readiness"], "blocked")
        self.assertEqual(row["execution_evidence"], "execution_manifest_metadata_conflict")
        self.assertIn("execution_manifest_detector_action_graph_conflict", row["blockers"])

    def test_execution_manifest_from_other_workspace_is_blocked(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        self._write_canonical_task_inputs(detector_slug)
        other_workspace = self.base / "other-workspace"
        other_workspace.mkdir()
        manifest = _proved_manifest(self.ws, "manual-rerun-other-workspace")
        manifest.update(
            {
                "candidate_id": "manual-rerun-other-workspace",
                "proof_task_id": "POQ-001",
                "detector_slug": detector_slug,
                "detector_obligation": "P-001",
                "detector_action_graph": ".auditooor/detector_action_graphs/hit_000_withdraw.json",
                "workspace": str(other_workspace),
            }
        )
        manifest["commands_attempted"][0]["cwd"] = str(other_workspace)
        _write_json(
            self.ws / "poc_execution" / "manual-rerun-other-workspace" / "execution_manifest.json",
            manifest,
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 0)
        row = result["rows"][0]
        self.assertEqual(row["proof_readiness"], "blocked")
        self.assertEqual(row["execution_evidence"], "execution_manifest_metadata_conflict")
        self.assertIn("execution_manifest_workspace_conflict", row["blockers"])
        self.assertIn("execution_manifest_command_cwd_conflict", row["blockers"])

    def test_ambiguous_proof_task_manifest_linkage_is_blocked_and_not_promoted(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        graph_path = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
        _write_json(graph_path, _action_graph(detector_slug))
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_withdraw.json"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            _canonical_proof_obligation_queue(detector_slug),
        )

        first_manifest = _proved_manifest(self.ws, "manual-rerun-001")
        first_manifest.update(
            {
                "candidate_id": "manual-rerun-001",
                "proof_task_id": "POQ-001",
                "detector_slug": detector_slug,
                "detector_obligation": "P-001",
                "detector_action_graph": ".auditooor/detector_action_graphs/hit_000_withdraw.json",
            }
        )
        _write_json(
            self.ws / "poc_execution" / "manual-rerun-001" / "execution_manifest.json",
            first_manifest,
        )

        second_manifest = _proved_manifest(self.ws, "manual-rerun-002")
        second_manifest.update(
            {
                "candidate_id": "manual-rerun-002",
                "proof_task_id": "POQ-001",
                "detector_slug": detector_slug,
                "detector_obligation": "P-001",
                "detector_action_graph": ".auditooor/detector_action_graphs/hit_000_withdraw.json",
                "final_result": "failed",
                "impact_assertion": "not_proved",
                "evidence_class": "executed_with_manifest",
            }
        )
        _write_json(
            self.ws / "poc_execution" / "manual-rerun-002" / "execution_manifest.json",
            second_manifest,
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertEqual(result["summary"]["rows_returned"], 1)
        self.assertEqual(
            result["summary"]["proved_impact_evidence_count"],
            0,
            "Ambiguous proof_task_id linkage must not promote proved-impact evidence.",
        )
        row = result["rows"][0]
        self.assertEqual(row["detector_slug"], detector_slug)
        self.assertEqual(row["proof_readiness"], "blocked")
        self.assertNotEqual(row["execution_evidence"], "proved_impact_evidence")
        self.assertFalse(row["promotion_allowed"])
        self.assertTrue(row["advisory_only"])
        ambiguity_markers = [
            row.get("execution_manifest_join", ""),
            row.get("poc_execution_record_status", ""),
            str(row.get("execution_manifest_ambiguity", "")),
            *(row.get("blockers") or []),
        ]
        self.assertTrue(
            any("ambig" in str(item).lower() for item in ambiguity_markers),
            "Ambiguous linkage should be explicitly surfaced in row metadata/blockers.",
        )

    def test_noncanonical_manifest_evidence_class_is_not_counted_as_proved_impact(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        graph_path = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
        _write_json(graph_path, _action_graph(detector_slug))
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_withdraw.json"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            _canonical_proof_obligation_queue(detector_slug),
        )
        manifest = _proved_manifest(self.ws, "manual-rerun-001")
        manifest.update(
            {
                "candidate_id": "manual-rerun-001",
                "proof_task_id": "POQ-001",
                "detector_slug": detector_slug,
                "detector_obligation": "P-001",
                "evidence_class": "proved_impact_evidence",
            }
        )
        _write_json(
            self.ws / "poc_execution" / "manual-rerun-001" / "execution_manifest.json",
            manifest,
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 0)
        row = result["rows"][0]
        self.assertEqual(row["proof_readiness"], "blocked")
        self.assertEqual(row["execution_evidence"], "manifest_present_unproved")
        self.assertIn("execution_manifest_not_canonical_executed_evidence", row["blockers"])

    def test_manifest_bool_exit_code_does_not_count_as_strict_proved_impact(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        self._write_canonical_task_inputs(detector_slug)
        manifest = _proved_manifest(self.ws, "manual-rerun-bool-exit")
        manifest.update(
            {
                "candidate_id": "manual-rerun-bool-exit",
                "proof_task_id": "POQ-001",
                "detector_slug": detector_slug,
                "detector_obligation": "P-001",
                "detector_action_graph": ".auditooor/detector_action_graphs/hit_000_withdraw.json",
            }
        )
        manifest["commands_attempted"][0]["exit_code"] = True
        _write_json(
            self.ws / "poc_execution" / "manual-rerun-bool-exit" / "execution_manifest.json",
            manifest,
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 0)
        row = result["rows"][0]
        self.assertEqual(row["execution_evidence"], "executed_with_manifest")
        self.assertEqual(row["proof_readiness"], "executed_with_manifest")
        self.assertIn("execution_manifest_not_proved_impact", row["blockers"])

    def test_manifest_legacy_string_commands_do_not_count_as_structured_execution_evidence(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        self._write_canonical_task_inputs(detector_slug)
        manifest = _proved_manifest(self.ws, "manual-rerun-legacy-command")
        manifest.update(
            {
                "candidate_id": "manual-rerun-legacy-command",
                "proof_task_id": "POQ-001",
                "detector_slug": detector_slug,
                "detector_obligation": "P-001",
                "detector_action_graph": ".auditooor/detector_action_graphs/hit_000_withdraw.json",
                "commands_attempted": ["forge test --match-test testWithdrawReentrancy"],
            }
        )
        _write_json(
            self.ws / "poc_execution" / "manual-rerun-legacy-command" / "execution_manifest.json",
            manifest,
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 0)
        self.assertEqual(result["summary"]["executed_with_manifest_count"], 0)
        row = result["rows"][0]
        self.assertEqual(row["proof_readiness"], "blocked")
        self.assertEqual(row["execution_evidence"], "manifest_present_unproved")
        self.assertIn("execution_manifest_not_canonical_executed_evidence", row["blockers"])

    def test_detector_slug_fallback_cannot_prove_tasked_queue_row(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        graph_path = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
        _write_json(graph_path, _action_graph(detector_slug))
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_withdraw.json"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            _canonical_proof_obligation_queue(detector_slug),
        )
        manifest = _proved_manifest(self.ws, detector_slug)
        manifest.pop("proof_task_id", None)
        manifest.pop("detector_obligation", None)
        manifest["candidate_id"] = detector_slug
        manifest["detector_slug"] = detector_slug
        _write_json(
            self.ws / "poc_execution" / detector_slug / "execution_manifest.json",
            manifest,
        )

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            detector_slug=detector_slug,
        )

        self.assertEqual(result["summary"]["proved_impact_evidence_count"], 0)
        row = result["rows"][0]
        self.assertEqual(row["proof_readiness"], "blocked")
        self.assertEqual(row["execution_manifest_join"], "candidate_id_or_detector_slug_fallback")
        self.assertEqual(row["execution_evidence"], "fallback_manifest_unbound")
        self.assertIn("execution_manifest_fallback_not_proof_task_bound", row["blockers"])

    def test_non_solidity_queue_rows_are_filtered(self) -> None:
        detector_slug = self._write_inputs(include_rust=True)

        result = self.vault.vault_solidity_detector_proof_context(
            workspace_path=str(self.ws),
            limit=8,
        )

        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertEqual(result["summary"]["queue_rows_seen"], 2)
        self.assertEqual(result["summary"]["non_solidity_rows_filtered"], 1)
        self.assertEqual(result["summary"]["rows_returned"], 1)
        self.assertEqual([row["detector_slug"] for row in result["rows"]], [detector_slug])
        self.assertTrue(all(row["language"] == "solidity" for row in result["rows"]))

    def test_canonical_proof_obligation_queue_and_tools_call_are_supported(self) -> None:
        detector_slug = "withdraw-reentrancy-no-guard"
        graph_path = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
        _write_json(graph_path, _action_graph(detector_slug))
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_withdraw.json"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            _canonical_proof_obligation_queue(detector_slug),
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.freshness.json",
            _proof_queue_freshness_marker(),
        )

        listed = self.vault_mcp.handle_request(
            self.vault,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        by_name = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertIn("vault_solidity_detector_proof_context", by_name)
        self.assertIn("workspace_path", by_name["vault_solidity_detector_proof_context"]["inputSchema"]["properties"])

        response = self.vault_mcp.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "vault_solidity_detector_proof_context",
                    "arguments": {"workspace_path": str(self.ws), "detector_slug": detector_slug},
                },
            },
        )
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["schema"], EXPECTED_SCHEMA)
        self.assertFalse(payload["degraded"], payload.get("degraded_reason"))
        self.assertEqual(payload["summary"]["queue_rows_seen"], 1)
        self.assertEqual(payload["rows"][0]["proof_readiness"], "ready_for_foundry_poc")
        self.assertEqual(payload["rows"][0]["action_graph"]["graph_ref"], ".auditooor/detector_action_graphs/hit_000_withdraw.json")
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])
        self.assertNotIn(str(self.base), json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
