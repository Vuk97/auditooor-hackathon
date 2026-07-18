from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-proof-hardening.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_proof_hardening", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanProofHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_dydx_iavl_critical_claim_requires_production_profile_gates(self) -> None:
        row = self.tool.infer_record_hardening(
            {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/cantina-202-abba",
                "source_audit_ref": "paste_ready/filed/cantina-202.md",
                "target_domain": "consensus",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": "iavl/nodedb deleteLegacyVersions Commit",
                "bug_class": "db-race",
                "attack_class": "iavl-pruning-race",
                "attacker_action_sequence": "MemDB AB-BA deadlock during Commit causes validator halt and needs restart evidence",
                "impact_class": "dos",
                "severity_at_finding": "critical",
                "verdict_class": "FILED",
            }
        )

        self.assertIn("R30", row["triggered_gates"])
        self.assertIn("R22", row["triggered_gates"])
        self.assertFalse(row["promotion_allowed"])
        self.assertTrue(row["advisory_only"])
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(row["result_class"], "discovery_analogy")
        self.assertEqual(row["severity_ceiling"], "none_without_local_target_proof")
        self.assertEqual(row["rubric_match_status"], "unverified_for_current_target")
        self.assertFalse(row["listed_impact_proven"])
        self.assertTrue(row["production_profile_required"])
        self.assertTrue(row["production_profile_constraints"]["persistent_backend"])
        self.assertTrue(any(gate["gate"] == "R30" for gate in row["gate_statuses"]))
        joined = "\n".join(row["required_before_high_critical"])
        self.assertIn("real persistent backend", joined)
        self.assertIn("reflection", joined)
        self.assertIn("multi-validator", joined)
        self.assertIn("restart", joined)

    def test_synthetic_candidate_is_shape_only_not_submit_ready(self) -> None:
        row = self.tool.infer_record_hardening(
            {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dsl/synthetic",
                "source_audit_ref": "canonical-dsl:patterns.dsl/example.yaml",
                "target_domain": "vault",
                "target_language": "solidity",
                "target_repo": "patterns/dsl",
                "target_component": "withdraw",
                "attack_class": "state-accounting-drift",
                "severity_at_finding": "high",
                "verdict_class": "CANDIDATE",
            }
        )

        self.assertEqual(row["evidence_class"], "synthetic_candidate_not_audit_verified")
        self.assertEqual(row["result_class"], "discovery_analogy")
        self.assertEqual(row["claim_boundary"], "shape_only_not_submit_ready")
        self.assertTrue(any("synthetic" in item for item in row["promotion_blockers"]))

    def test_solodit_skeleton_signature_gets_shape_blocker(self) -> None:
        row = self.tool.infer_record_hardening(
            {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "solodit-spec:31103:8416c703c329",
                "source_audit_ref": "solodit-spec:detectors/_specs/drafts_solodit/example.yaml:31103",
                "target_domain": "vault",
                "target_language": "solidity",
                "target_repo": "sherlock/tapioca",
                "target_component": "mTOFT",
                "function_shape": {
                    "raw_signature": "function mintFee() internal returns (bool)",
                    "shape_tags": ["protocol-invariant-bypass"],
                },
                "attack_class": "protocol-invariant-bypass",
                "severity_at_finding": "high",
            }
        )

        self.assertEqual(row["function_shape_confidence"], "skeleton_signature")
        self.assertTrue(any("skeleton function signature" in item for item in row["promotion_blockers"]))

    def test_solodit_function_name_hint_gets_shape_blocker(self) -> None:
        row = self.tool.infer_record_hardening(
            {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "solodit-spec:31103:8416c703c329",
                "source_audit_ref": "solodit-spec:detectors/_specs/drafts_solodit/example.yaml:31103",
                "target_domain": "vault",
                "target_language": "solidity",
                "target_repo": "sherlock/tapioca",
                "target_component": "mTOFT",
                "function_shape": {
                    "raw_signature": "function-name-hint: mintFee",
                    "shape_tags": ["protocol-invariant-bypass", "inferred-function-name"],
                },
                "attack_class": "protocol-invariant-bypass",
                "severity_at_finding": "high",
            }
        )

        self.assertEqual(row["function_shape_confidence"], "function_name_hint")
        self.assertTrue(any("function-name hint" in item for item in row["promotion_blockers"]))

    def test_cosmos_iavl_storage_record_requires_production_profile(self) -> None:
        row = self.tool.infer_record_hardening(
            {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "cosmos/iavl-nodedb",
                "source_audit_ref": "staging/dydx-iavl-reformatted-root-recovery-1007-HIGH.md",
                "target_language": "go",
                "target_repo": "cosmos/iavl",
                "target_component": "nodedb.go",
                "bug_class": "missing-close-pruning-shutdown-deadlock",
                "attack_class": "graceful-shutdown-deadlock",
                "severity_at_finding": "HIGH",
                "verdict_class": "FILED",
            }
        )

        self.assertIn("R30", row["triggered_gates"])
        self.assertTrue(row["production_profile_required"])

    def test_safe_proof_artifact_is_carried_into_sidecar_and_maturity(self) -> None:
        row = self.tool.infer_record_hardening(
            {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "paste-ready/example",
                "source_audit_ref": "paste_ready/filed/example.md",
                "target_language": "solidity",
                "target_repo": "example/repo",
                "target_component": "Vault",
                "attack_class": "share-inflation",
                "severity_at_finding": "high",
                "verdict_class": "FILED",
                "proof_artifact_path": "poc_execution/share_inflation.log",
            }
        )

        self.assertEqual(row["proof_artifacts"], ["poc_execution/share_inflation.log"])
        self.assertEqual(row["proof_maturity_score"], 5)
        self.assertTrue(
            all("poc_execution/share_inflation.log" in gate["evidence_refs"] for gate in row["gate_statuses"])
        )

    def test_unsafe_proof_artifact_is_not_carried(self) -> None:
        row = self.tool.infer_record_hardening(
            {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "paste-ready/example",
                "source_audit_ref": "paste_ready/filed/example.md",
                "target_language": "solidity",
                "target_repo": "example/repo",
                "target_component": "Vault",
                "attack_class": "share-inflation",
                "severity_at_finding": "high",
                "verdict_class": "FILED",
                "proof_artifact_path": "/tmp/share_inflation.log",
            }
        )

        self.assertEqual(row["proof_artifacts"], [])
        self.assertEqual(row["proof_maturity_score"], 4)

    def test_cli_writes_jsonl(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-proof-hardening-") as tmp:
            root = Path(tmp)
            tags = root / "tags"
            out = root / "proof.jsonl"
            tags.mkdir()
            (tags / "record.yaml").write_text(
                """
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:example:123456789abc
source_audit_ref: solodit-spec:detectors/_specs/example.yaml:1
target_domain: vault
target_language: solidity
target_repo: example/repo
target_component: Vault
function_shape:
  raw_signature: "function withdraw(uint256 amount) external"
  shape_tags:
    - state-accounting-drift
bug_class: accounting
attack_class: state-accounting-drift
attacker_role: unprivileged
attacker_action_sequence: attacker withdraws stale accounting balance
required_preconditions:
  - funded vault
impact_class: theft
impact_actor: arbitrary-user
impact_dollar_class: "$100K-$1M"
fix_pattern: update accounting before transfer
fix_anti_pattern_avoided: public corpus summary overclaim
severity_at_finding: high
year: 2024
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            rc = self.tool.main(["--tag-dir", str(tags), "--out", str(out)])

            self.assertEqual(rc, 0)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(rows[0]["record_id"], "solodit-spec:example:123456789abc")
            self.assertEqual(rows[0]["evidence_class"], "public_corpus_precedent")

    def test_cli_includes_v1_1_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-proof-hardening-v11-") as tmp:
            root = Path(tmp)
            tags = root / "tags"
            out = root / "proof.jsonl"
            tags.mkdir()
            (tags / "record.yaml").write_text(
                """
schema_version: auditooor.hackerman_record.v1.1
record_id: submission-derived:dydx:v1-1-proof:abc123
source_audit_ref: submission-derived:dydx:submissions/paste_ready/example.md
record_tier: submission-derived
source_extraction_method: human-curated
source_extraction_confidence: 0.9
target_domain: dex
target_language: go
target_repo: dydxprotocol/v4-chain
target_component: AccountPlus withdrawal validation
bug_class: validation-bypass
attack_class: permission-scope-bypass
attacker_role: unprivileged
attacker_action_sequence: permissioned key withdraws from non-whitelisted subaccount
required_preconditions:
  - permissioned key exists
impact_class: theft
impact_actor: specific-user
impact_dollar_class: "$100K-$1M"
fix_pattern: validate subaccount filter on withdrawal
fix_anti_pattern_avoided: trusting authorization setup only
severity_at_finding: critical
year: 2026
proof_artifact_path: audits/dydx/poc-tests/accountplus.log
verification_tier: tier-3-synthetic-taxonomy-anchored
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            rc = self.tool.main(["--tag-dir", str(tags), "--out", str(out)])

            self.assertEqual(rc, 0)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["record_id"], "submission-derived:dydx:v1-1-proof:abc123")
            self.assertEqual(rows[0]["proof_artifacts"], ["audits/dydx/poc-tests/accountplus.log"])


class HackermanProofHardeningShardingTest(unittest.TestCase):
    """J3e sharding tests for proof_hardening emitter."""

    def _minimal_tag(self, tag_dir: Path, name: str, record_id: str) -> None:
        tag_dir.mkdir(parents=True, exist_ok=True)
        (tag_dir / f"{name}.yaml").write_text(
            f"""
schema_version: auditooor.hackerman_record.v1
record_id: {record_id}
source_audit_ref: audit:test:{name}
target_language: go
target_repo: example/repo
target_component: x/bank/keeper.go
bug_class: access-control
attack_class: access-control
notes: sharding test record
""".lstrip(),
            encoding="utf-8",
        )

    def test_shard_emit_creates_manifest_and_shard_dir(self) -> None:
        import subprocess, sys as _sys
        TOOL_PH = REPO_ROOT / "tools" / "hackerman-proof-hardening.py"
        with tempfile.TemporaryDirectory(prefix="proof-shard-emit-") as tmp:
            root = Path(tmp)
            tags = root / "tags"
            for i in range(3):
                self._minimal_tag(tags, f"rec{i}", f"test/rec-{i}")
            out = root / "proof_hardening.jsonl"
            proc = subprocess.run(
                [_sys.executable, str(TOOL_PH), "--tag-dir", str(tags),
                 "--out", str(out), "--shard-target-mb", "0.001"],
                cwd=REPO_ROOT, text=True, capture_output=True, check=True,
            )
            summary = json.loads(proc.stdout.strip())
            self.assertEqual(summary["schema"], "auditooor.hackerman_proof_hardening.manifest.v1")
            self.assertGreater(summary["shard_count"], 0)
            self.assertGreater(summary["records_emitted"], 0)

            manifest_path = out.with_name("proof_hardening.manifest.json")
            shard_dir = out.with_name("proof_hardening.d")
            self.assertTrue(manifest_path.is_file(), "manifest.json must exist")
            self.assertTrue(shard_dir.is_dir(), "shard dir must exist")
            self.assertEqual(out.stat().st_size, 0, "monolith must be 0-byte stub")

    def test_shard_aware_read_jsonl_loads_proof_rows(self) -> None:
        """read_jsonl must load proof_hardening rows from shards transparently."""
        import sys as _sys, subprocess
        _sys.path.insert(0, str(REPO_ROOT / "tools"))
        from hackerman_query_common import read_jsonl  # noqa: PLC0415
        TOOL_PH = REPO_ROOT / "tools" / "hackerman-proof-hardening.py"

        with tempfile.TemporaryDirectory(prefix="proof-shard-read-") as tmp:
            root = Path(tmp)
            tags = root / "tags"
            for i in range(3):
                self._minimal_tag(tags, f"rec{i}", f"test/read-rec-{i}")
            out = root / "proof_hardening.jsonl"
            subprocess.run(
                [_sys.executable, str(TOOL_PH), "--tag-dir", str(tags),
                 "--out", str(out), "--shard-target-mb", "0.001"],
                cwd=REPO_ROOT, text=True, capture_output=True, check=True,
            )

            rows = read_jsonl(out)
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(r.get("record_id") for r in rows))


if __name__ == "__main__":
    unittest.main()
