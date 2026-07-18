from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-chain-candidates.py"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run_json(tag_dir: Path, limit: int = 10) -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--tag-dir",
            str(tag_dir),
            "--limit",
            str(limit),
            "--json",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


def _run_json_args(tag_dir: Path, *extra: str) -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--tag-dir",
            str(tag_dir),
            *extra,
            "--json",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


class HackermanChainCandidatesTest(unittest.TestCase):
    def test_ranking_prefers_diverse_high_signal_function_group(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-chain-ranking-") as tmp:
            tags = Path(tmp) / "tags"
            _write(
                tags / "vault-access.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/vault/access
source_audit_ref: audit:alpha:access
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: contracts/Vault.sol
function_shape:
  raw_signature: "function deposit(uint256 assets, address receiver) external"
  shape_tags:
    - auth-before-share-mint
bug_class: access-control
attack_class: access-control-missing-modifier
severity_at_finding: high
impact_class: theft
record_quality_score: 4.5
verdict_class: FILED
attacker_action_sequence: missing gate before mint
required_preconditions:
  - deposit is callable before share mint finalization
proof_artifact_path: contracts/Vault.sol
""".lstrip(),
            )
            _write(
                tags / "vault-oracle.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/vault/oracle
source_audit_ref: audit:alpha:oracle
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: contracts/Vault.sol
function_shape:
  raw_signature: "function deposit(uint256 assets, address receiver) external"
  shape_tags:
    - stale-price-before-accounting
bug_class: stale-oracle
attack_class: oracle-staleness
severity_at_finding: high
impact_class: theft
record_quality_score: 4.0
verdict_class: FILED
attacker_action_sequence: stale price drives shares
""".lstrip(),
            )
            _write(
                tags / "vault-reentrancy.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/vault/reentrant
source_audit_ref: audit:alpha:reentrant
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: contracts/Vault.sol
function_shape:
  raw_signature: "function deposit(uint256 assets, address receiver) external"
  shape_tags:
    - callback-before-final-accounting
bug_class: reentrancy
attack_class: callback-reentrancy
severity_at_finding: medium
impact_class: freeze
record_quality_score: 3.5
verdict_class: SUBMITTED
attacker_action_sequence: callback observes partial accounting
""".lstrip(),
            )
            _write(
                tags / "router-low-a.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/router/a
source_audit_ref: audit:beta:a
target_domain: dex
target_language: solidity
target_repo: example/protocol
target_component: contracts/Router.sol
function_shape:
  raw_signature: "function execute(bytes calldata data) external"
  shape_tags:
    - calldata-forwarding
bug_class: input-validation
attack_class: malformed-calldata
severity_at_finding: low
impact_class: griefing
record_quality_score: 2.0
verdict_class: CANDIDATE
attacker_action_sequence: malformed call
""".lstrip(),
            )
            _write(
                tags / "router-low-b.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/router/b
source_audit_ref: audit:beta:b
target_domain: dex
target_language: solidity
target_repo: example/protocol
target_component: contracts/Router.sol
function_shape:
  raw_signature: "function execute(bytes calldata data) external"
  shape_tags:
    - unchecked-return
bug_class: unchecked-call
attack_class: unchecked-low-level-call
severity_at_finding: low
impact_class: griefing
record_quality_score: 2.0
verdict_class: CANDIDATE
attacker_action_sequence: unchecked call
""".lstrip(),
            )

            payload = _run_json(tags)

            self.assertEqual(payload["total_records_loaded"], 5)
            self.assertGreaterEqual(payload["total_candidates"], 2)
            top = payload["candidates"][0]
            self.assertEqual(top["group"]["anchor_level"], "function")
            self.assertEqual(top["group"]["function_anchor"], "deposit")
            self.assertEqual(top["record_count"], 3)
            self.assertEqual(top["bug_families"], ["access-control", "reentrancy", "stale-oracle"])
            self.assertIn("callback-reentrancy", top["attack_classes"])
            self.assertEqual(top["submission_posture"], "candidate_not_submit_ready")
            self.assertGreater(top["actionability_score"], 0)
            obligation_kinds = {item["kind"] for item in top["proof_obligations"]}
            self.assertIn("chain_ordering", obligation_kinds)
            self.assertIn("anchor_reachability", obligation_kinds)
            self.assertIn("record_precondition", obligation_kinds)
            self.assertIn("proof_artifact", obligation_kinds)
            self.assertTrue(
                all(item["submission_gate"] == "required_before_submission" for item in top["proof_obligations"])
            )
            self.assertIn("all proof_obligations", top["not_submit_ready_until"][0])
            self.assertGreater(top["score"], payload["candidates"][1]["score"])

    def test_groups_legacy_and_v1_records_by_functionish_anchor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-chain-grouping-") as tmp:
            tags = Path(tmp) / "tags"
            _write(
                tags / "legacy.yaml",
                """
verdict_id: legacy/exec-replay
target_repo: example/bridge
language: solidity
verdict_class: FILED
bug_class: signature-replay
severity_claimed: HIGH
attack_classes_to_try:
  - signature-replay-no-nonce
sites:
  - file_path: contracts/Bridge.sol
    function_signature: "function execute(bytes calldata sig) external"
    shape_hash: abcdefabcdefabcd
notes: replay execute signature
""".lstrip(),
            )
            _write(
                tags / "native.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: native/bridge/access
source_audit_ref: audit:bridge:access
target_domain: bridge
target_language: solidity
target_repo: example/bridge
target_component: contracts/Bridge.sol
function_shape:
  raw_signature: "function execute(bytes calldata sig) external"
  shape_tags:
    - executor-auth
bug_class: access-control
attack_class: executor-auth-bypass
severity_at_finding: medium
impact_class: theft
record_quality_score: 3.0
verdict_class: SUBMITTED
attacker_action_sequence: bypass executor auth
""".lstrip(),
            )

            payload = _run_json(tags)

            self.assertEqual(payload["total_records_loaded"], 2)
            self.assertEqual(payload["total_candidates"], 1)
            candidate = payload["candidates"][0]
            self.assertEqual(candidate["group"]["scope"], "example/bridge")
            self.assertEqual(candidate["group"]["component_anchor"], "contracts/bridge.sol")
            self.assertEqual(candidate["group"]["function_anchor"], "execute")
            self.assertEqual(
                sorted(record["record_id"] for record in candidate["records"]),
                ["legacy/exec-replay", "native/bridge/access"],
            )
            self.assertEqual(candidate["bug_families"], ["access-control", "signature-replay"])

    def test_default_filters_broad_unknown_evm_bucket(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-chain-generic-") as tmp:
            tags = Path(tmp) / "tags"
            for suffix, bug_class in (("a", "reentrancy"), ("b", "oracle-manipulation")):
                _write(
                    tags / f"generic-{suffix}.yaml",
                    f"""
schema_version: auditooor.hackerman_record.v1
record_id: rec/generic/{suffix}
source_audit_ref: corpus-mined:generic-{suffix}
target_domain: defi
target_language: solidity
target_repo: unknown
target_component: evm
function_shape:
  raw_signature: "function EVM() external"
  shape_tags:
    - evm
bug_class: {bug_class}
attack_class: {bug_class}
severity_at_finding: high
impact_class: griefing
record_quality_score: 3.0
verdict_class: FILED
attacker_action_sequence: generic corpus bucket
""".lstrip(),
                )

            default_payload = _run_json(tags)
            generic_payload = _run_json_args(tags, "--include-generic")

            self.assertEqual(default_payload["total_candidates"], 0)
            self.assertFalse(default_payload["include_generic"])
            self.assertEqual(generic_payload["total_candidates"], 1)
            self.assertTrue(generic_payload["include_generic"])

    def test_empty_corpus_is_valid_empty_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-chain-empty-") as tmp:
            tags = Path(tmp) / "tags"
            tags.mkdir()

            payload = _run_json(tags)

            self.assertEqual(payload["total_records_loaded"], 0)
            self.assertEqual(payload["groups_considered"], 0)
            self.assertEqual(payload["total_candidates"], 0)
            self.assertEqual(payload["candidates"], [])

    def test_markdown_renders_proof_obligations_and_not_submit_ready_gate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-chain-markdown-") as tmp:
            tags = Path(tmp) / "tags"
            _write(
                tags / "bridge-replay.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/bridge/replay
source_audit_ref: audit:bridge:replay
target_language: solidity
target_repo: example/bridge
target_component: contracts/Bridge.sol
function_shape:
  raw_signature: "function execute(bytes calldata message) external"
bug_class: signature-replay
attack_class: signature-replay-no-nonce
severity_at_finding: high
impact_class: theft
record_quality_score: 4.0
verdict_class: FILED
attacker_action_sequence: replay old message
required_preconditions:
  - message domain does not bind chain id or nonce
""".lstrip(),
            )
            _write(
                tags / "bridge-auth.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/bridge/auth
source_audit_ref: audit:bridge:auth
target_language: solidity
target_repo: example/bridge
target_component: contracts/Bridge.sol
function_shape:
  raw_signature: "function execute(bytes calldata message) external"
bug_class: executor-auth-bypass
attack_class: access-control-missing-modifier
severity_at_finding: high
impact_class: theft
record_quality_score: 4.0
verdict_class: FILED
attacker_action_sequence: call execute without authorized relayer
proof_artifact_path: contracts/Bridge.sol
""".lstrip(),
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--tag-dir", str(tags), "--limit", "5"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=True,
            )

            self.assertIn("Submission posture: `candidate_not_submit_ready`", proc.stdout)
            self.assertIn("Proof obligations:", proc.stdout)
            self.assertIn("[record_precondition]", proc.stdout)
            self.assertIn("[proof_artifact]", proc.stdout)
            self.assertIn("Not submit ready until:", proc.stdout)


if __name__ == "__main__":
    unittest.main()
