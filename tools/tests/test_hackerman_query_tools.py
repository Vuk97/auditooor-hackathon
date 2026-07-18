#!/usr/bin/env python3
"""Regression tests for the initial hackerman index-backed CLIs."""
from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run_json(*args: str) -> dict:
    proc = subprocess.run(
        [sys.executable, *args, "--json"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


class HackermanQueryToolsTest(unittest.TestCase):
    def test_attack_class_evidence_loads_legacy_tag_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-ac-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            _write(
                index_dir / "by_attack_class.jsonl",
                json.dumps(
                    {
                        "key": "signature-lazy-execution",
                        "tag_file": "legacy.yaml",
                        "verdict_id": "legacy/1",
                    }
                )
                + "\n",
            )
            _write(
                tags_dir / "legacy.yaml",
                """
verdict_id: legacy/1
target_repo: example/protocol
language: solidity
verdict_class: FILED
bug_class: signature-validation
severity_claimed: HIGH
poc_path: /tmp/unsafe-poc.log
attack_classes_to_try:
  - signature-lazy-execution
sites:
  - file_path: src/Vault.sol
    function_signature: "function execute(bytes calldata sig) external"
    shape_hash: abcdefabcdefabcd
notes: real legacy verdict
""".lstrip(),
            )

            out = _run_json(
                "tools/attack-class-evidence.py",
                "signature_lazy_execution",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "5",
            )

            self.assertFalse(out["degraded"])
            self.assertEqual(out["total_records_matched"], 1)
            self.assertEqual(out["records"][0]["record_id"], "legacy/1")
            self.assertEqual(out["records"][0]["target_language"], "solidity")
            self.assertEqual(out["records"][0]["attack_class"], "signature-lazy-execution")
            self.assertEqual(out["records"][0]["proof_artifact_path"], "")

    def test_attack_class_evidence_supports_embedded_hackerman_record_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-ac-embedded-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            _write(
                index_dir / "by_attack_class.jsonl",
                json.dumps(
                    {
                        "key": "oracle-staleness",
                        "record": {
                            "schema_version": "auditooor.hackerman_record.v1",
                            "record_id": "rec-1",
                            "source_audit_ref": "solodit:oracle:1",
                            "target_domain": "oracle",
                            "target_language": "solidity",
                            "target_repo": "example/oracle",
                            "bug_class": "stale-oracle",
                            "attack_class": "oracle-staleness",
                            "attacker_action_sequence": "Step 1: wait for stale price",
                            "severity_at_finding": "high",
                            "proof_artifact_path": "poc_execution/oracle_stale.log",
                        },
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/attack-class-evidence.py",
                "oracle-staleness",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
            )

            self.assertEqual(out["total_records_matched"], 1)
            self.assertEqual(out["records"][0]["record_id"], "rec-1")
            self.assertEqual(out["records"][0]["attacker_action_sequence"], "Step 1: wait for stale price")
            self.assertEqual(out["records"][0]["proof_artifact_path"], "poc_execution/oracle_stale.log")

    def test_attack_class_evidence_unknown_is_empty_not_degraded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-ac-empty-") as tmp:
            root = Path(tmp)
            _write(root / "index" / "by_attack_class.jsonl", "")
            out = _run_json(
                "tools/attack-class-evidence.py",
                "missing-class",
                "--index-dir",
                str(root / "index"),
                "--tags-dir",
                str(root / "tags"),
            )
            self.assertFalse(out["degraded"])
            self.assertEqual(out["total_records_matched"], 0)
            self.assertEqual(out["records"], [])

    def test_attack_class_evidence_does_not_cite_missing_quality_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-ac-no-quality-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            missing_quality = root / "derived" / "record_quality.jsonl"
            _write(
                index_dir / "by_attack_class.jsonl",
                json.dumps(
                    {
                        "key": "admin-bypass",
                        "record": {
                            "record_id": "rec/admin",
                            "target_language": "go",
                            "attack_class": "admin-bypass",
                        },
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/attack-class-evidence.py",
                "admin-bypass",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--quality-sidecar",
                str(missing_quality),
                "--limit",
                "1",
            )

            self.assertFalse(out["quality_sidecar_loaded"])
            self.assertNotIn(str(missing_quality), out["source_refs"])
            self.assertEqual(out["sidecar_gaps"][0]["label"], "record_quality")
            self.assertEqual(out["sidecar_gaps"][0]["reason"], "missing")

    def test_attack_class_evidence_expands_signature_lazy_execution_alias(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-ac-alias-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            _write(
                index_dir / "by_attack_class.jsonl",
                json.dumps(
                    {
                        "key": "signature-replay-no-nonce",
                        "record": {
                            "schema_version": "auditooor.hackerman_record.v1",
                            "record_id": "sig/no-nonce",
                            "source_audit_ref": "audit:sig:1",
                            "target_domain": "bridge",
                            "target_language": "solidity",
                            "target_repo": "example/bridge",
                            "bug_class": "signature-replay",
                            "attack_class": "signature-replay-no-nonce",
                            "attacker_action_sequence": "replay an authorization without nonce burn",
                            "severity_at_finding": "high",
                        },
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/attack-class-evidence.py",
                "signature_lazy_execution",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
            )

            self.assertEqual(out["query_terms"][0], "signature_lazy_execution")
            self.assertEqual(out["total_records_matched"], 1)
            self.assertEqual(out["records"][0]["record_id"], "sig/no-nonce")

    def test_attack_class_evidence_sorts_by_quality_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-ac-quality-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            quality = root / "record_quality.jsonl"
            low = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "generic/admin-bypass",
                "source_audit_ref": "solodit:admin:1",
                "target_language": "go",
                "target_repo": "generic/go",
                "bug_class": "admin-bypass",
                "attack_class": "admin-bypass",
                "verdict_class": "FILED",
            }
            high = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/admin-bypass",
                "source_audit_ref": "paste_ready/filed/dydx-admin.md",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "bug_class": "admin-bypass",
                "attack_class": "admin-bypass",
                "verdict_class": "FILED",
            }
            _write(
                index_dir / "by_attack_class.jsonl",
                json.dumps({"key": "admin-bypass", "record": low}) + "\n"
                + json.dumps({"key": "admin-bypass", "record": high}) + "\n",
            )
            _write(
                quality,
                json.dumps(
                    {
                        "record_id": "generic/admin-bypass",
                        "record_tier": "public-corpus",
                        "record_quality_score": 2.0,
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "record_id": "dydx/admin-bypass",
                        "record_tier": "dydx-filed",
                        "record_quality_score": 5.0,
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/attack-class-evidence.py",
                "admin-bypass",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--quality-sidecar",
                str(quality),
                "--limit",
                "2",
            )

            self.assertTrue(out["quality_sidecar_loaded"])
            self.assertEqual(out["records"][0]["record_id"], "dydx/admin-bypass")
            self.assertEqual(out["records"][0]["record_tier"], "dydx-filed")
            self.assertEqual(out["records"][0]["record_quality_score"], 5.0)
            self.assertEqual(out["records"][1]["record_id"], "generic/admin-bypass")

    def test_attack_class_evidence_loads_proof_hardening_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-ac-proof-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            proof = root / "derived" / "proof_hardening.jsonl"
            record = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/cantina-202-abba",
                "source_audit_ref": "paste_ready/filed/cantina-202.md",
                "target_domain": "consensus",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "bug_class": "iavl-pruning-race",
                "attack_class": "iavl-pruning-race",
                "verdict_class": "FILED",
            }
            _write(index_dir / "by_attack_class.jsonl", json.dumps({"key": "iavl-pruning-race", "record": record}) + "\n")
            _write(
                proof,
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_hardening.v1",
                        "record_id": "dydx/cantina-202-abba",
                        "source_audit_ref": "paste_ready/filed/cantina-202.md",
                        "advisory_only": True,
                        "promotion_allowed": False,
                        "submission_posture": "NOT_SUBMIT_READY",
                        "evidence_class": "submission_or_filed_precedent",
                        "proof_maturity_score": 3,
                        "claim_boundary": "precedent_requires_reproduction_under_target_production_profile",
                        "triggered_gates": ["L29-FILING", "R30"],
                        "required_before_high_critical": ["real persistent backend", "multi-validator proof"],
                        "promotion_blockers": ["production-profile proof required before High/Critical promotion"],
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/attack-class-evidence.py",
                "iavl-pruning-race",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--proof-hardening-sidecar",
                str(proof),
            )

            self.assertTrue(out["proof_hardening_sidecar_loaded"])
            self.assertIn(str(proof), out["source_refs"])
            hardening = out["records"][0]["proof_hardening"]
            self.assertEqual(hardening["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(hardening["promotion_allowed"])
            self.assertIn("R30", hardening["triggered_gates"])

    def test_attack_class_evidence_ranks_precise_proof_above_function_hint(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-ac-proof-rank-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            proof = root / "derived" / "proof_hardening.jsonl"
            precise = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "precise/admin-bypass",
                "source_audit_ref": "prior-audit:precise",
                "target_language": "go",
                "target_repo": "cosmos/cosmos-sdk",
                "bug_class": "admin-bypass",
                "attack_class": "admin-bypass",
                "verdict_class": "FILED",
            }
            weak = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "weak/admin-bypass",
                "source_audit_ref": "solodit-spec:weak",
                "target_language": "go",
                "target_repo": "cosmos/cosmos-sdk",
                "bug_class": "admin-bypass",
                "attack_class": "admin-bypass",
                "verdict_class": "FILED",
            }
            _write(
                index_dir / "by_attack_class.jsonl",
                json.dumps({"key": "admin-bypass", "record": weak}) + "\n"
                + json.dumps({"key": "admin-bypass", "record": precise}) + "\n",
            )
            _write(
                proof,
                json.dumps(
                    {
                        "record_id": "weak/admin-bypass",
                        "source_audit_ref": "solodit-spec:weak",
                        "promotion_allowed": False,
                        "submission_posture": "NOT_SUBMIT_READY",
                        "function_shape_confidence": "function_name_hint",
                        "proof_maturity_score": 1,
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "record_id": "precise/admin-bypass",
                        "source_audit_ref": "prior-audit:precise",
                        "promotion_allowed": True,
                        "submission_posture": "PROOF_REFERENCE",
                        "function_shape_confidence": "source_extracted_signature",
                        "proof_maturity_score": 5,
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/attack-class-evidence.py",
                "admin-bypass",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--proof-hardening-sidecar",
                str(proof),
                "--limit",
                "2",
            )

            self.assertEqual(out["records"][0]["record_id"], "precise/admin-bypass")
            self.assertEqual(out["records"][1]["record_id"], "weak/admin-bypass")

    def test_function_mindset_queries_shape_hash_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-fn-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            shape = "0123456789abcdef"
            _write(
                index_dir / "by_shape_hash.jsonl",
                json.dumps({"key": shape, "tag_file": "shape.yaml", "verdict_id": "shape/1"}) + "\n",
            )
            _write(
                tags_dir / "shape.yaml",
                f"""
verdict_id: shape/1
target_repo: example/go-chain
language: go
verdict_class: FILED
bug_class: msg-server-auth
attack_classes_to_try:
  - admin-bypass
sites:
  - file_path: x/foo/keeper/msg_server.go
    function_signature: "func (k msgServer) Update(ctx context.Context, msg *types.MsgUpdate) (*types.MsgUpdateResponse, error)"
    shape_hash: {shape}
notes: real shape match
""".lstrip(),
            )

            out = _run_json(
                "tools/function-mindset.py",
                "--shape-hash",
                shape,
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "3",
            )

            self.assertFalse(out["degraded"])
            self.assertEqual(out["total_records_matched"], 1)
            self.assertEqual(out["ranked_attack_classes"][0]["attack_class"], "admin-bypass")
            self.assertEqual(out["ranked_attack_classes"][0]["evidence"][0]["shape_hash"], shape)

    def test_function_mindset_queries_sharded_function_shape_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-fn-shard-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            shape = "fedcba9876543210"
            shard = hashlib.sha256(shape.encode("utf-8")).hexdigest()[:2]
            _write(
                index_dir / "by_function_shape.d" / f"{shard}.jsonl",
                json.dumps({"key": shape, "tag_file": "shape.yaml", "verdict_id": "shape/1"}) + "\n",
            )
            _write(index_dir / "by_function_shape.d" / "manifest.json", "{}\n")
            _write(
                tags_dir / "shape.yaml",
                f"""
verdict_id: shape/1
target_repo: example/go-chain
language: go
verdict_class: FILED
bug_class: msg-server-auth
attack_classes_to_try:
  - admin-bypass
sites:
  - file_path: x/foo/keeper/msg_server.go
    function_signature: "func (k msgServer) Update(ctx context.Context, msg *types.MsgUpdate) (*types.MsgUpdateResponse, error)"
    shape_hash: {shape}
notes: sharded shape match
""".lstrip(),
            )

            out = _run_json(
                "tools/function-mindset.py",
                "--shape-hash",
                shape,
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "3",
            )

            self.assertFalse(out["degraded"])
            self.assertEqual(out["total_records_matched"], 1)
            self.assertEqual(out["ranked_attack_classes"][0]["attack_class"], "admin-bypass")

    def test_function_mindset_evidence_sorting_uses_quality_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-fn-quality-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            quality = root / "record_quality.jsonl"
            shape = "0123456789abcdef"
            low = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "generic/msg-server-auth",
                "source_audit_ref": "solodit:go:1",
                "target_language": "go",
                "target_repo": "generic/go-chain",
                "bug_class": "msg-server-auth",
                "attack_class": "admin-bypass",
            }
            high = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/msg-server-auth",
                "source_audit_ref": "paste_ready/filed/dydx-auth.md",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "bug_class": "msg-server-auth",
                "attack_class": "admin-bypass",
            }
            _write(
                index_dir / "by_shape_hash.jsonl",
                json.dumps({"key": shape, "record": low}) + "\n"
                + json.dumps({"key": shape, "record": high}) + "\n",
            )
            _write(index_dir / "by_function_shape.jsonl", "")
            _write(
                quality,
                json.dumps(
                    {
                        "record_id": "generic/msg-server-auth",
                        "record_tier": "public-corpus",
                        "record_quality_score": 2.2,
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "record_id": "dydx/msg-server-auth",
                        "record_tier": "dydx-filed",
                        "record_quality_score": 5.0,
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/function-mindset.py",
                "--shape-hash",
                shape,
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--quality-sidecar",
                str(quality),
                "--limit",
                "3",
            )

            self.assertTrue(out["quality_sidecar_loaded"])
            evidence = out["ranked_attack_classes"][0]["evidence"]
            self.assertEqual(evidence[0]["record_id"], "dydx/msg-server-auth")
            self.assertEqual(evidence[0]["record_tier"], "dydx-filed")
            self.assertEqual(evidence[0]["record_quality_score"], 5.0)
            self.assertEqual(evidence[1]["record_id"], "generic/msg-server-auth")

    def test_function_mindset_loads_proof_hardening_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-fn-proof-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            proof = root / "derived" / "proof_hardening.jsonl"
            shape = "0123456789abcdef"
            record = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/cantina-202-abba",
                "source_audit_ref": "paste_ready/filed/cantina-202.md",
                "target_domain": "consensus",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "bug_class": "iavl-pruning-race",
                "attack_class": "iavl-pruning-race",
                "function_shape": {"raw_signature": "func (ndb *nodeDB) deleteLegacyVersions()"},
            }
            _write(index_dir / "by_shape_hash.jsonl", json.dumps({"key": shape, "record": record}) + "\n")
            _write(index_dir / "by_function_shape.jsonl", "")
            _write(
                proof,
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_hardening.v1",
                        "record_id": "dydx/cantina-202-abba",
                        "source_audit_ref": "paste_ready/filed/cantina-202.md",
                        "advisory_only": True,
                        "promotion_allowed": False,
                        "submission_posture": "NOT_SUBMIT_READY",
                        "evidence_class": "submission_or_filed_precedent",
                        "proof_maturity_score": 3,
                        "claim_boundary": "precedent_requires_reproduction_under_target_production_profile",
                        "triggered_gates": ["L29-FILING", "R18", "R19", "R22", "R30"],
                        "required_before_high_critical": ["FinalizeBlock/Commit reproduction", "restart behavior transcript"],
                        "promotion_blockers": ["production-profile proof required before High/Critical promotion"],
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/function-mindset.py",
                "--shape-hash",
                shape,
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--proof-hardening-sidecar",
                str(proof),
                "--limit",
                "1",
            )

            self.assertTrue(out["proof_hardening_sidecar_loaded"])
            evidence = out["ranked_attack_classes"][0]["evidence"][0]
            self.assertEqual(evidence["proof_hardening"]["submission_posture"], "NOT_SUBMIT_READY")
            self.assertIn("R30", evidence["proof_hardening"]["triggered_gates"])

    def test_function_mindset_loads_cross_language_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-fn-xlang-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            sidecar = root / "derived" / "cross_language_analogues.jsonl"
            shape = "0123456789abcdef"
            record = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "solidity/share-inflation",
                "source_audit_ref": "prior-audit:share-inflation",
                "target_domain": "vault",
                "target_language": "solidity",
                "target_repo": "example/vault",
                "bug_class": "share-inflation",
                "attack_class": "first-deposit-share-inflation",
                "function_shape": {"raw_signature": "function deposit(uint256 assets) external"},
            }
            _write(index_dir / "by_shape_hash.jsonl", json.dumps({"key": shape, "record": record}) + "\n")
            _write(index_dir / "by_function_shape.jsonl", "")
            _write(
                sidecar,
                json.dumps(
                    {
                        "source_record_id": "solidity/share-inflation",
                        "target_language": "go",
                        "pattern_translation": "solidity first-deposit share inflation -> go zero-share vault residual",
                        "analogue_record_id": "go/zero-share-residual",
                        "confidence": 0.82,
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/function-mindset.py",
                "--shape-hash",
                shape,
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--cross-language-sidecar",
                str(sidecar),
                "--language",
                "go",
                "--limit",
                "1",
            )

            self.assertTrue(out["cross_language_sidecar_loaded"])
            self.assertEqual(out["cross_language_sidecar_sources_loaded"], 1)
            evidence = out["ranked_attack_classes"][0]["evidence"][0]
            self.assertEqual(evidence["cross_language_analogues"][0]["target_language"], "go")
            self.assertEqual(evidence["cross_language_analogues"][0]["analogue_record_id"], "go/zero-share-residual")

    def test_function_mindset_penalizes_function_hint_bucket_score(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-fn-proof-rank-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            proof = root / "derived" / "proof_hardening.jsonl"
            shape = "0123456789abcdef"
            rows = []
            proof_rows = []
            for idx in range(4):
                record_id = f"weak/admin-bypass-{idx}"
                record = {
                    "schema_version": "auditooor.hackerman_record.v1",
                    "record_id": record_id,
                    "source_audit_ref": f"solodit-spec:weak:{idx}",
                    "target_language": "go",
                    "target_repo": "cosmos/cosmos-sdk",
                    "bug_class": "weak-admin-bypass",
                    "attack_class": "weak-admin-bypass",
                }
                rows.append(json.dumps({"key": shape, "record": record}))
                proof_rows.append(
                    json.dumps(
                        {
                            "record_id": record_id,
                            "source_audit_ref": f"solodit-spec:weak:{idx}",
                            "promotion_allowed": False,
                            "submission_posture": "NOT_SUBMIT_READY",
                            "function_shape_confidence": "function_name_hint",
                            "proof_maturity_score": 1,
                        }
                    )
                )
            strong = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "strong/admin-bypass",
                "source_audit_ref": "prior-audit:strong",
                "target_language": "go",
                "target_repo": "cosmos/cosmos-sdk",
                "bug_class": "strong-admin-bypass",
                "attack_class": "strong-admin-bypass",
            }
            rows.append(json.dumps({"key": shape, "record": strong}))
            proof_rows.append(
                json.dumps(
                    {
                        "record_id": "strong/admin-bypass",
                        "source_audit_ref": "prior-audit:strong",
                        "promotion_allowed": True,
                        "submission_posture": "PROOF_REFERENCE",
                        "function_shape_confidence": "source_extracted_signature",
                        "proof_maturity_score": 5,
                    }
                )
            )
            _write(index_dir / "by_shape_hash.jsonl", "\n".join(rows) + "\n")
            _write(index_dir / "by_function_shape.jsonl", "")
            _write(proof, "\n".join(proof_rows) + "\n")

            out = _run_json(
                "tools/function-mindset.py",
                "--shape-hash",
                shape,
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--proof-hardening-sidecar",
                str(proof),
                "--limit",
                "2",
            )

            ranked = out["ranked_attack_classes"]
            self.assertEqual(ranked[0]["attack_class"], "strong-admin-bypass")
            self.assertLess(ranked[1]["score"], ranked[0]["score"])

    def test_function_mindset_exact_file_shape_beats_same_repo_off_file_prior(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-fn-specificity-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            quality = root / "record_quality.jsonl"
            shape = "0123456789abcdef"
            target_file = "protocol/x/clob/types/operations_to_propose.go"
            exact = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/clob-exact",
                "source_audit_ref": "local:dydx:clob",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": target_file,
                "bug_class": "clob-queue-race",
                "attack_class": "clob-queue-race",
                "sites": [{"file_path": target_file, "shape_hash": shape}],
            }
            noisy_prior = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/accountplus-admin-prior",
                "source_audit_ref": "paste_ready/filed/cantina-311.md",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": "protocol/x/accountplus/ante/ante.go",
                "bug_class": "permission-filter-bypass",
                "attack_class": "admin-bypass",
                "sites": [{"file_path": "protocol/x/accountplus/ante/ante.go", "shape_hash": shape}],
            }
            _write(index_dir / "by_shape_hash.jsonl", json.dumps({"key": shape, "record": exact}) + "\n")
            _write(index_dir / "by_function_shape.jsonl", json.dumps({"key": shape, "record": noisy_prior}) + "\n")
            _write(
                quality,
                json.dumps(
                    {
                        "record_id": "dydx/clob-exact",
                        "record_tier": "local-workspace",
                        "record_quality_score": 2.0,
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "record_id": "dydx/accountplus-admin-prior",
                        "record_tier": "dydx-filed",
                        "record_quality_score": 5.0,
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/function-mindset.py",
                "--shape-hash",
                shape,
                "--target-repo",
                "dydxprotocol/v4-chain",
                "--file-path",
                target_file,
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--quality-sidecar",
                str(quality),
                "--limit",
                "2",
            )

            ranked = out["ranked_attack_classes"]
            self.assertEqual(ranked[0]["attack_class"], "clob-queue-race")
            self.assertEqual(ranked[0]["evidence"][0]["record_id"], "dydx/clob-exact")
            self.assertEqual(ranked[0]["evidence"][0]["match_kind"], "coarse_exact")
            self.assertEqual(ranked[0]["evidence"][0]["match_weight"], 0.45)
            self.assertEqual(ranked[1]["attack_class"], "admin-bypass")
            self.assertEqual(ranked[1]["evidence"][0]["match_kind"], "function_shape_coarse")
            self.assertLess(ranked[1]["evidence"][0]["match_weight"], 0.45)

    def test_hackerman_brief_for_lane_uses_language_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-") as tmp:
            root = Path(tmp)
            workspace = root / "ws"
            index_dir = root / "index"
            tags_dir = root / "tags"
            _write(workspace / "src" / "Target.go", "package target\nfunc Execute() {}\n")
            _write(
                index_dir / "by_language.jsonl",
                json.dumps({"key": "go", "tag_file": "go.yaml", "verdict_id": "go/1"}) + "\n",
            )
            _write(
                tags_dir / "go.yaml",
                """
verdict_id: go/1
target_repo: example/go-chain
language: go
verdict_class: FILED
bug_class: fee-redirect
attack_classes_to_try:
  - fee-redirect
sites:
  - file_path: x/bank/keeper/send.go
notes: real go prior
""".lstrip(),
            )

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H1-send",
                "--scope-glob",
                "src/*.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "2",
            )

            self.assertFalse(out["degraded"])
            self.assertEqual(out["target"]["language"], "go")
            self.assertEqual(out["records"][0]["record_id"], "go/1")
            self.assertIn("go/1", out["brief_markdown"])

    def test_hackerman_brief_for_lane_loads_full_tag_when_index_projects_record_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-full-tag-") as tmp:
            root = Path(tmp)
            workspace = root / "dydx"
            index_dir = root / "index"
            tags_dir = root / "tags"
            _write(workspace / "protocol" / "app" / "abci.go", "package app\n")
            _write(
                index_dir / "by_language.jsonl",
                json.dumps(
                    {
                        "key": "go",
                        "record_id": "prior-audit:dydx:abci",
                        "source_audit_ref": "prior-audit:dydx:prior_audits/report.txt:L1:S1",
                        "target_repo": "dydxprotocol/v4-chain",
                        "tag_file": "prior.yaml",
                    }
                )
                + "\n",
            )
            _write(
                tags_dir / "prior.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: prior-audit:dydx:abci
source_audit_ref: prior-audit:dydx:prior_audits/report.txt:L1:S1
target_domain: consensus
target_language: go
target_repo: dydxprotocol/v4-chain
target_component: protocol/app/abci.go
bug_class: consensus
attack_class: consensus-state
attacker_action_sequence: full tag sequence survives projected index row
severity_at_finding: medium
""".lstrip(),
            )

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H-dydx-abci",
                "--files",
                "protocol/app/abci.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "1",
            )

            self.assertEqual(out["records"][0]["target_component"], "protocol/app/abci.go")
            self.assertEqual(out["records"][0]["attacker_action_sequence"], "full tag sequence survives projected index row")

    def test_hackerman_brief_for_lane_ranks_liquity_fork_terms_over_generic_lending(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-liquity-") as tmp:
            root = Path(tmp)
            workspace = root / "mezo-liquity-fork"
            index_dir = root / "index"
            tags_dir = root / "tags"
            _write(
                workspace / "contracts" / "BorrowerOperations.sol",
                "contract BorrowerOperations { function openTrove() external {} }\n"
                "contract StabilityPool { function offset() external {} }\n",
            )
            generic = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "generic/lending-share-accounting",
                "source_audit_ref": "prior:lending:generic",
                "target_domain": "lending",
                "target_language": "solidity",
                "target_repo": "example/lending-protocol",
                "target_component": "contracts/Vault.sol",
                "bug_class": "collateral-accounting",
                "attack_class": "accounting-bypass",
                "attacker_action_sequence": "exploit generic collateral accounting",
                "notes": "generic lending prior",
            }
            liquity = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "mezo/liquity-trove-stabilitypool",
                "source_audit_ref": "prior:mezo-liquity:trove",
                "target_domain": "lending",
                "target_language": "solidity",
                "target_repo": "mezo/liquity-fork",
                "target_component": "contracts/BorrowerOperations.sol",
                "bug_class": "liquity-trove-accounting",
                "attack_class": "trove-collateral-bypass",
                "attacker_action_sequence": "manipulate a Liquity trove through BorrowerOperations and StabilityPool",
                "sites": [{"file_path": "contracts/BorrowerOperations.sol"}],
                "notes": "Mezo Liquity fork trove and stability pool issue",
            }
            _write(
                index_dir / "by_target_domain.jsonl",
                json.dumps({"key": "lending", "record": generic}) + "\n"
                + json.dumps({"key": "lending", "record": liquity}) + "\n",
            )
            _write(index_dir / "by_language.jsonl", "")

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H2-mezo-liquity-fork",
                "--files",
                "contracts/BorrowerOperations.sol",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "2",
            )

            self.assertEqual(out["target"]["domain"], "lending")
            self.assertEqual(out["records"][0]["record_id"], "mezo/liquity-trove-stabilitypool")
            self.assertEqual(out["records"][1]["record_id"], "generic/lending-share-accounting")

    def test_hackerman_brief_for_lane_ranks_cosmos_sdk_file_terms_over_generic_go(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-dydx-") as tmp:
            root = Path(tmp)
            workspace = root / "dydx-v4-chain"
            index_dir = root / "index"
            tags_dir = root / "tags"
            _write(
                workspace / "protocol" / "x" / "clob" / "keeper" / "msg_server.go",
                "package keeper\n"
                "func (k msgServer) PlaceOrder(ctx sdk.Context, msg *types.MsgPlaceOrder) error { return nil }\n",
            )
            generic = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "generic/go-handler-bypass",
                "source_audit_ref": "prior:go:generic",
                "target_domain": "dex",
                "target_language": "go",
                "target_repo": "example/go-app",
                "target_component": "cmd/server/main.go",
                "bug_class": "handler-auth",
                "attack_class": "admin-bypass",
                "attacker_action_sequence": "call a generic go handler",
                "notes": "generic Go server issue",
            }
            dydx = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/cosmos-clob-msg-server",
                "source_audit_ref": "prior:dydx:v4-chain:clob",
                "target_domain": "dex",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": "protocol/x/clob/keeper/msg_server.go",
                "bug_class": "cosmos-sdk-msg-server-auth",
                "attack_class": "keeper-order-bypass",
                "attacker_action_sequence": "submit a Cosmos SDK MsgPlaceOrder through the dYdX CLOB keeper",
                "sites": [{"file_path": "protocol/x/clob/keeper/msg_server.go"}],
                "notes": "dYdX cosmos-sdk keeper clob prior",
            }
            _write(
                index_dir / "by_language.jsonl",
                json.dumps({"key": "go", "record": generic}) + "\n"
                + json.dumps({"key": "go", "record": dydx}) + "\n",
            )

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H4-dydx-cosmos-sdk-clob",
                "--files",
                "protocol/x/clob/keeper/msg_server.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "2",
            )

            self.assertEqual(out["target"]["language"], "go")
            self.assertEqual(out["records"][0]["record_id"], "dydx/cosmos-clob-msg-server")
            self.assertEqual(out["records"][1]["record_id"], "generic/go-handler-bypass")

    def test_hackerman_brief_for_lane_demotes_synthetic_candidates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-candidate-") as tmp:
            root = Path(tmp)
            workspace = root / "solidity-fork"
            index_dir = root / "index"
            tags_dir = root / "tags"
            _write(workspace / "src" / "Target.sol", "contract Target { function withdraw() external {} }\n")
            synthetic = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dsl/synthetic-withdraw",
                "source_audit_ref": "dsl_pattern/synthetic-withdraw",
                "target_domain": "vault",
                "target_language": "solidity",
                "target_repo": "patterns/dsl",
                "target_component": "src/Target.sol",
                "bug_class": "withdrawal-ordering",
                "attack_class": "state-accounting-drift",
                "attacker_action_sequence": "synthetic Target withdraw pattern",
                "verdict_class": "CANDIDATE",
            }
            verified = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "audit/verified-withdraw",
                "source_audit_ref": "solodit:verified:1",
                "target_domain": "vault",
                "target_language": "solidity",
                "target_repo": "example/vault",
                "target_component": "src/Other.sol",
                "bug_class": "withdrawal-ordering",
                "attack_class": "state-accounting-drift",
                "attacker_action_sequence": "verified withdrawal accounting issue",
                "verdict_class": "FILED",
            }
            _write(
                index_dir / "by_language.jsonl",
                json.dumps({"key": "solidity", "record": synthetic}) + "\n"
                + json.dumps({"key": "solidity", "record": verified}) + "\n",
            )

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H5-target-withdraw",
                "--files",
                "src/Target.sol",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "2",
            )

            self.assertEqual(out["records"][0]["record_id"], "audit/verified-withdraw")
            self.assertEqual(out["records"][1]["record_id"], "dsl/synthetic-withdraw")
            self.assertEqual(out["record_groups"]["audit_verified"], 1)
            self.assertEqual(out["record_groups"]["synthetic_candidates"], 1)
            marker = "## Synthetic pattern candidates (NOT audit-verified)"
            self.assertIn(marker, out["brief_markdown"])
            self.assertLess(out["brief_markdown"].index("audit/verified-withdraw"), out["brief_markdown"].index(marker))
            self.assertLess(out["brief_markdown"].index(marker), out["brief_markdown"].index("dsl/synthetic-withdraw"))

    def test_hackerman_brief_for_lane_quality_sidecar_prioritizes_dydx_go_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-quality-") as tmp:
            root = Path(tmp)
            workspace = root / "dydx"
            index_dir = root / "index"
            tags_dir = root / "tags"
            quality = root / "record_quality.jsonl"
            _write(workspace / "protocol" / "x" / "clob" / "keeper" / "msg_server.go", "package keeper\n")
            generic = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "generic/go-clob-msg-server",
                "source_audit_ref": "solodit-spec:generic",
                "target_domain": "dex",
                "target_language": "go",
                "target_repo": "generic/go",
                "target_component": "protocol/x/clob/keeper/msg_server.go",
                "bug_class": "keeper-order-bypass",
                "attack_class": "keeper-order-bypass",
                "attacker_action_sequence": "generic clob msg server bypass",
            }
            dydx = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/filed-clob-msg-server",
                "source_audit_ref": "paste_ready/filed/dydx-clob.md",
                "target_domain": "dex",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": "protocol/x/clob/keeper/msg_server.go",
                "bug_class": "keeper-order-bypass",
                "attack_class": "keeper-order-bypass",
                "attacker_action_sequence": "filed dYdX clob issue",
            }
            _write(
                index_dir / "by_language.jsonl",
                json.dumps({"key": "go", "record": generic}) + "\n"
                + json.dumps({"key": "go", "record": dydx}) + "\n",
            )
            _write(
                quality,
                json.dumps(
                    {
                        "record_id": "generic/go-clob-msg-server",
                        "record_tier": "public-corpus",
                        "record_quality_score": 2.4,
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "record_id": "dydx/filed-clob-msg-server",
                        "record_tier": "dydx-filed",
                        "record_quality_score": 5.0,
                        "source_extraction_method": "human-curated",
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H4-dydx-cosmos-sdk-clob",
                "--files",
                "protocol/x/clob/keeper/msg_server.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--quality-sidecar",
                str(quality),
                "--limit",
                "2",
            )

            self.assertTrue(out["quality_sidecar_loaded"])
            self.assertEqual(out["records"][0]["record_id"], "dydx/filed-clob-msg-server")
            self.assertEqual(out["records"][0]["record_tier"], "dydx-filed")
            self.assertEqual(out["records"][0]["record_quality_score"], 5.0)
            self.assertIn("Quality: dydx-filed / 5.0", out["brief_markdown"])

    def test_hackerman_brief_for_lane_exact_file_match_beats_off_file_quality(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-file-rank-") as tmp:
            root = Path(tmp)
            workspace = root / "dydx"
            index_dir = root / "index"
            tags_dir = root / "tags"
            quality = root / "record_quality.jsonl"
            _write(workspace / "protocol" / "x" / "clob" / "keeper" / "msg_server.go", "package keeper\n")
            exact = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "generic/exact-clob-msg-server",
                "source_audit_ref": "solodit-spec:exact",
                "target_domain": "dex",
                "target_language": "go",
                "target_repo": "generic/go",
                "target_component": "protocol/x/clob/keeper/msg_server.go",
                "bug_class": "keeper-order-bypass",
                "attack_class": "keeper-order-bypass",
                "attacker_action_sequence": "exact clob msg server analogue",
            }
            off_file = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/filed-off-file",
                "source_audit_ref": "paste_ready/filed/dydx-off-file.md",
                "target_domain": "dex",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": "protocol/x/listing/keeper/msg_server.go",
                "bug_class": "keeper-order-bypass",
                "attack_class": "keeper-order-bypass",
                "attacker_action_sequence": "filed but off-file dYdX issue",
            }
            _write(
                index_dir / "by_language.jsonl",
                json.dumps({"key": "go", "record": off_file}) + "\n"
                + json.dumps({"key": "go", "record": exact}) + "\n",
            )
            _write(
                quality,
                json.dumps(
                    {
                        "record_id": "generic/exact-clob-msg-server",
                        "record_tier": "public-corpus",
                        "record_quality_score": 2.0,
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "record_id": "dydx/filed-off-file",
                        "record_tier": "dydx-filed",
                        "record_quality_score": 5.0,
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H4-dydx-cosmos-sdk-clob",
                "--files",
                "protocol/x/clob/keeper/msg_server.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--quality-sidecar",
                str(quality),
                "--limit",
                "2",
            )

            self.assertEqual(out["records"][0]["record_id"], "generic/exact-clob-msg-server")
            self.assertEqual(out["records"][1]["record_id"], "dydx/filed-off-file")

    def test_hackerman_brief_for_lane_loads_cross_language_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-xlang-") as tmp:
            root = Path(tmp)
            workspace = root / "dydx"
            index_dir = root / "index"
            tags_dir = root / "tags"
            sidecar = tags_dir.parent / "derived" / "cross_language_analogues.jsonl"
            _write(workspace / "protocol" / "x" / "clob" / "keeper" / "msg_server.go", "package keeper\n")
            record = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/go-clob-msg-server",
                "source_audit_ref": "prior:dydx:clob",
                "target_domain": "dex",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": "protocol/x/clob/keeper/msg_server.go",
                "bug_class": "keeper-order-bypass",
                "attack_class": "keeper-order-bypass",
                "attacker_action_sequence": "submit a Cosmos SDK MsgPlaceOrder through the dYdX CLOB keeper",
            }
            _write(index_dir / "by_language.jsonl", json.dumps({"key": "go", "record": record}) + "\n")
            _write(
                sidecar,
                json.dumps(
                    {
                        "source_record_id": "dydx/go-clob-msg-server",
                        "source_language": "go",
                        "target_language": "solidity",
                        "analogue_record_id": "solidity/order-bypass",
                        "attack_class": "keeper-order-bypass",
                        "confidence": 0.9,
                        "pattern_translation": "go->solidity: keeper authority check -> modifier/role gate",
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H4-dydx-cosmos-sdk-clob",
                "--files",
                "protocol/x/clob/keeper/msg_server.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "1",
            )

            self.assertTrue(out["cross_language_sidecar_loaded"])
            self.assertEqual(out["cross_language_sidecar_sources_loaded"], 1)
            self.assertEqual(out["records"][0]["cross_language_analogues"][0]["target_language"], "solidity")
            self.assertIn("keeper authority check", out["brief_markdown"])

    def test_hackerman_brief_for_lane_reports_missing_sidecars_as_gaps(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-missing-sidecars-") as tmp:
            root = Path(tmp)
            workspace = root / "dydx"
            index_dir = root / "index"
            tags_dir = root / "tags"
            quality = root / "derived" / "record_quality.jsonl"
            xlang = root / "derived" / "cross_language_analogues.jsonl"
            proof = root / "derived" / "proof_hardening.jsonl"
            _write(workspace / "protocol" / "x" / "clob" / "keeper" / "msg_server.go", "package keeper\n")
            _write(
                index_dir / "by_language.jsonl",
                json.dumps(
                    {
                        "key": "go",
                        "record": {
                            "record_id": "dydx/go-clob-msg-server",
                            "target_language": "go",
                            "target_domain": "dex",
                            "attack_class": "keeper-order-bypass",
                        },
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H4-dydx-cosmos-sdk-clob",
                "--files",
                "protocol/x/clob/keeper/msg_server.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--quality-sidecar",
                str(quality),
                "--cross-language-sidecar",
                str(xlang),
                "--proof-hardening-sidecar",
                str(proof),
                "--limit",
                "1",
            )

            self.assertFalse(out["quality_sidecar_loaded"])
            self.assertFalse(out["cross_language_sidecar_loaded"])
            self.assertFalse(out["proof_hardening_sidecar_loaded"])
            self.assertNotIn(str(quality), out["source_refs"])
            self.assertNotIn(str(xlang), out["source_refs"])
            self.assertNotIn(str(proof), out["source_refs"])
            self.assertEqual(
                {gap["label"] for gap in out["sidecar_gaps"]},
                {"record_quality", "cross_language_analogues", "proof_hardening"},
            )

    def test_hackerman_brief_for_lane_loads_proof_hardening_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-proof-hardening-") as tmp:
            root = Path(tmp)
            workspace = root / "dydx"
            index_dir = root / "index"
            tags_dir = root / "tags"
            proof = root / "derived" / "proof_hardening.jsonl"
            _write(workspace / "protocol" / "x" / "iavl" / "nodedb.go", "package iavl\n")
            record = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/cantina-202-abba",
                "source_audit_ref": "paste_ready/filed/cantina-202.md",
                "target_domain": "consensus",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": "iavl/nodedb.go",
                "bug_class": "iavl-pruning-race",
                "attack_class": "iavl-pruning-race",
                "attacker_action_sequence": "Commit path can halt validators",
            }
            _write(index_dir / "by_language.jsonl", json.dumps({"key": "go", "record": record}) + "\n")
            _write(
                proof,
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_hardening.v1",
                        "record_id": "dydx/cantina-202-abba",
                        "source_audit_ref": "paste_ready/filed/cantina-202.md",
                        "advisory_only": True,
                        "promotion_allowed": False,
                        "submission_posture": "NOT_SUBMIT_READY",
                        "evidence_class": "submission_or_filed_precedent",
                        "proof_maturity_score": 3,
                        "claim_boundary": "precedent_requires_reproduction_under_target_production_profile",
                        "triggered_gates": ["L29-FILING", "R22", "R30"],
                        "required_before_high_critical": ["real persistent backend", "multi-validator proof"],
                        "promotion_blockers": ["production-profile proof required before High/Critical promotion"],
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H4-dydx-iavl-commit-race",
                "--files",
                "protocol/x/iavl/nodedb.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--proof-hardening-sidecar",
                str(proof),
                "--limit",
                "1",
            )

            self.assertTrue(out["proof_hardening_sidecar_loaded"])
            self.assertIn("R30", out["claim_hardening"]["triggered_gates"])
            self.assertEqual(out["records"][0]["proof_hardening"]["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(out["records"][0]["proof_hardening"]["promotion_allowed"])
            self.assertIn("## Claim Hardening", out["brief_markdown"])
            self.assertIn("promotion_allowed=false", out["brief_markdown"])

    def test_hackerman_brief_for_lane_surfaces_workspace_prior_audit_context(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-brief-prior-audit-") as tmp:
            root = Path(tmp)
            workspace = root / "dydx"
            index_dir = root / "index"
            tags_dir = root / "tags"
            quality = root / "record_quality.jsonl"
            _write(workspace / "protocol" / "app" / "abci.go", "package app\n")
            filed = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/filed-slinky",
                "source_audit_ref": "paste_ready/filed/dydx-slinky.md",
                "target_domain": "oracle",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": "protocol/app/abci.go",
                "bug_class": "oracle-manipulation",
                "attack_class": "stale-or-manipulated-oracle",
                "attacker_action_sequence": "filed dYdX oracle issue",
            }
            prior = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "prior-audit:dydx:slinky:L1:S1",
                "source_audit_ref": "prior-audit:dydx:prior_audits/Informal.txt:L1:S1",
                "target_domain": "oracle",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "target_component": "Slinky's ValidateExtendedCommitAgainstLastCommit",
                "bug_class": "oracle-manipulation",
                "attack_class": "stale-or-manipulated-oracle",
                "attacker_action_sequence": "prior audit Slinky oracle validation issue",
            }
            _write(
                index_dir / "by_language.jsonl",
                json.dumps({"key": "go", "record": filed}) + "\n"
                + json.dumps({"key": "go", "record": prior}) + "\n",
            )
            _write(
                quality,
                json.dumps(
                    {
                        "record_id": "dydx/filed-slinky",
                        "record_tier": "dydx-filed",
                        "record_quality_score": 5.0,
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "record_id": "prior-audit:dydx:slinky:L1:S1",
                        "record_tier": "local-workspace",
                        "record_quality_score": 4.45,
                    }
                )
                + "\n",
            )

            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "H-dydx-slinky",
                "--files",
                "protocol/app/abci.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--quality-sidecar",
                str(quality),
                "--limit",
                "1",
            )

            self.assertEqual(out["records"][0]["record_id"], "dydx/filed-slinky")
            self.assertEqual(out["workspace_prior_audit_records"][0]["record_id"], "prior-audit:dydx:slinky:L1:S1")
            self.assertEqual(out["record_groups"]["workspace_prior_audit"], 1)
            self.assertIn("## Workspace prior-audit context", out["brief_markdown"])
            self.assertIn("prior-audit:dydx:slinky:L1:S1", out["brief_markdown"])


class HackermanBriefForLaneB2CrossLanguageAutoLiftTests(unittest.TestCase):
    """B2 (EXEC-WAVE-2-MULTI): verify the top-level Cross-Language
    Analogues section is auto-injected when the lane spans 2+ languages
    (or matches a known trigger repo) and is absent in single-language
    lanes / when suppressed via --no-cross-language-autolift."""

    def _build_xlang_fixture(self, root: Path, *, sol_file: bool, go_file: bool) -> tuple[Path, Path, Path]:
        workspace = root / "dydx-mixed"
        index_dir = root / "index"
        tags_dir = root / "tags"
        sidecar = tags_dir.parent / "derived" / "cross_language_analogues.jsonl"
        if sol_file:
            _write(workspace / "contracts" / "Vault.sol", "contract Vault {}\n")
        if go_file:
            _write(workspace / "protocol" / "x" / "clob" / "keeper" / "msg_server.go", "package keeper\n")
        record_go = {
            "schema_version": "auditooor.hackerman_record.v1",
            "record_id": "dydx/go-clob-msg-server",
            "source_audit_ref": "prior:dydx:clob",
            "target_domain": "dex",
            "target_language": "go",
            "target_repo": "dydxprotocol/v4-chain",
            "target_component": "protocol/x/clob/keeper/msg_server.go",
            "bug_class": "keeper-order-bypass",
            "attack_class": "keeper-order-bypass",
            "attacker_action_sequence": "submit a Cosmos SDK MsgPlaceOrder",
        }
        _write(index_dir / "by_language.jsonl", json.dumps({"key": "go", "record": record_go}) + "\n")
        _write(
            sidecar,
            json.dumps(
                {
                    "source_record_id": "dydx/go-clob-msg-server",
                    "source_language": "go",
                    "target_language": "solidity",
                    "analogue_record_id": "solidity/order-bypass-modifier-gate",
                    "attack_class": "keeper-order-bypass",
                    "confidence": 0.9,
                    "pattern_translation": "go->solidity: keeper authority check -> modifier/role gate",
                }
            )
            + "\n",
        )
        return workspace, index_dir, tags_dir

    def test_b2_autolift_fires_on_two_language_span(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b2-xlang-2lang-") as tmp:
            root = Path(tmp)
            workspace, index_dir, tags_dir = self._build_xlang_fixture(root, sol_file=True, go_file=True)
            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "B2-xlang-2lang",
                "--files",
                "contracts/Vault.sol,protocol/x/clob/keeper/msg_server.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "1",
            )
            autolift = out.get("cross_language_analogues_autolift") or {}
            self.assertTrue(
                autolift.get("trigger_fires"),
                f"B2: expected autolift trigger to fire on 2-language span, got {autolift}",
            )
            self.assertGreaterEqual(autolift.get("aggregated_count", 0), 1)
            self.assertIn("solidity", autolift.get("languages_span") or [])
            self.assertIn("go", autolift.get("languages_span") or [])
            self.assertIn("## Cross-Language Analogues", out["brief_markdown"])
            self.assertIn("keeper authority check", out["brief_markdown"])

    def test_b2_autolift_does_not_fire_on_single_language_no_trigger_repo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b2-xlang-1lang-") as tmp:
            root = Path(tmp)
            # Workspace name avoids any known trigger-repo substring.
            workspace_name = "private-vault-engagement-xyz"
            workspace = root / workspace_name
            index_dir = root / "index"
            tags_dir = root / "tags"
            sidecar = tags_dir.parent / "derived" / "cross_language_analogues.jsonl"
            _write(workspace / "src" / "Vault.sol", "contract Vault {}\n")
            _write(
                index_dir / "by_language.jsonl",
                json.dumps(
                    {
                        "key": "solidity",
                        "record": {
                            "schema_version": "auditooor.hackerman_record.v1",
                            "record_id": "synthetic/sol-vault",
                            "source_audit_ref": "synthetic:sol-vault",
                            "target_domain": "vault",
                            "target_language": "solidity",
                            "target_repo": "private-vault-engagement-xyz/contracts",
                            "target_component": "Vault.sol",
                            "bug_class": "logic-error",
                            "attack_class": "protocol-invariant-bypass",
                            "attacker_action_sequence": "submit a tx",
                        },
                    }
                )
                + "\n",
            )
            _write(sidecar, "")
            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "B2-xlang-1lang",
                "--files",
                "src/Vault.sol",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "1",
            )
            autolift = out.get("cross_language_analogues_autolift") or {}
            self.assertFalse(
                autolift.get("trigger_fires"),
                f"B2: expected autolift NOT to fire on single-language lane "
                f"without trigger repo, got {autolift}",
            )
            self.assertEqual(autolift.get("aggregated_count", 0), 0)
            self.assertNotIn("## Cross-Language Analogues", out["brief_markdown"])

    def test_b2_autolift_suppressed_via_cli_flag(self) -> None:
        with tempfile.TemporaryDirectory(prefix="b2-xlang-suppress-") as tmp:
            root = Path(tmp)
            workspace, index_dir, tags_dir = self._build_xlang_fixture(root, sol_file=True, go_file=True)
            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "B2-xlang-suppress",
                "--files",
                "contracts/Vault.sol,protocol/x/clob/keeper/msg_server.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--limit",
                "1",
                "--no-cross-language-autolift",
            )
            autolift = out.get("cross_language_analogues_autolift") or {}
            self.assertFalse(autolift.get("trigger_fires"))
            self.assertTrue(autolift.get("suppressed"))
            self.assertNotIn("## Cross-Language Analogues", out["brief_markdown"])

    def test_b2_autolift_fires_on_trigger_repo_match_single_language(self) -> None:
        """Even a single-language lane should get the section when the
        workspace name matches a CROSS_LANGUAGE_TRIGGER_REPOS substring
        (e.g. dydxprotocol/v4-chain)."""
        with tempfile.TemporaryDirectory(prefix="b2-xlang-trigger-repo-") as tmp:
            root = Path(tmp)
            workspace, index_dir, tags_dir = self._build_xlang_fixture(root, sol_file=False, go_file=True)
            out = _run_json(
                "tools/hackerman-brief-for-lane.py",
                "--workspace",
                str(workspace),
                "--lane-id",
                "B2-xlang-trigger",
                "--files",
                "protocol/x/clob/keeper/msg_server.go",
                "--index-dir",
                str(index_dir),
                "--tags-dir",
                str(tags_dir),
                "--target-repo",
                "dydxprotocol/v4-chain",
                "--limit",
                "1",
            )
            autolift = out.get("cross_language_analogues_autolift") or {}
            self.assertTrue(
                autolift.get("trigger_fires"),
                f"B2: expected autolift to fire via trigger-repo match, got {autolift}",
            )
            self.assertIn(
                "dydxprotocol/v4-chain",
                autolift.get("trigger_repos") or [],
            )


if __name__ == "__main__":
    unittest.main()
