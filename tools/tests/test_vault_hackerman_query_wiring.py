#!/usr/bin/env python3
"""Focused MCP tests for index-backed hackerman query wiring."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
CHAIN_SIDECAR_PATH = REPO_ROOT / "tools" / "hackerman-chain-candidates-sidecar.py"
CHAIN_UNIFY_SIDECAR_PATH = REPO_ROOT / "tools" / "hackerman-chain-unify-sidecar.py"
DETECTOR_SIDECAR_PATH = REPO_ROOT / "tools" / "hackerman-detector-relationships-sidecar.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_hackerman_wiring", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SERVER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vault_mcp_server_hackerman_wiring"] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_chain_sidecar_module():
    spec = importlib.util.spec_from_file_location("hackerman_chain_candidates_sidecar", CHAIN_SIDECAR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {CHAIN_SIDECAR_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_detector_sidecar_module():
    spec = importlib.util.spec_from_file_location(
        "hackerman_detector_relationships_sidecar",
        DETECTOR_SIDECAR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {DETECTOR_SIDECAR_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_chain_unify_sidecar_module():
    spec = importlib.util.spec_from_file_location(
        "hackerman_chain_unify_sidecar",
        CHAIN_UNIFY_SIDECAR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {CHAIN_UNIFY_SIDECAR_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


SERVER = _load_server_module()
CHAIN_SIDECAR = _load_chain_sidecar_module()
CHAIN_UNIFY_SIDECAR = _load_chain_unify_sidecar_module()
DETECTOR_SIDECAR = _load_detector_sidecar_module()


class VaultHackermanQueryWiringTest(unittest.TestCase):
    def _vault(self):
        return SERVER.VaultQuery(SERVER.Path(REPO_ROOT), repo_root=REPO_ROOT)

    def test_attack_class_evidence_merges_index_backed_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-ac-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            _write(
                index_dir / "by_attack_class.jsonl",
                json.dumps({"key": "oracle-staleness", "tag_file": "oracle.yaml", "verdict_id": "rec/oracle"})
                + "\n",
            )
            _write(
                tags_dir / "oracle.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/oracle
source_audit_ref: audit:oracle:1
target_domain: oracle
target_language: solidity
target_repo: example/oracle
target_component: Oracle.price
function_shape:
  raw_signature: "function price() external view returns (uint256)"
  shape_tags:
    - external-view-price-read
bug_class: stale-oracle
attack_class: oracle-staleness
attacker_role: unprivileged
attacker_action_sequence: "wait for stale price"
required_preconditions: []
impact_class: theft
impact_actor: borrowers
impact_dollar_class: "$100K-$1M"
fix_pattern: check updatedAt freshness
fix_anti_pattern_avoided: trusting stale price
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )

            out = self._vault().vault_attack_class_evidence(
                attack_class="oracle-staleness",
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
            )

            self.assertFalse(out.get("degraded"))
            self.assertEqual(out["schema"], SERVER.ATTACK_CLASS_EVIDENCE_SCHEMA)
            self.assertEqual(out["hackerman_query"]["total_records_matched"], 1)
            self.assertEqual(out["records"][0]["record_id"], "rec/oracle")
            self.assertTrue(
                any(row.get("record_id") == "rec/oracle" for row in out["exemplar_verdicts"])
            )
            self.assertFalse(out["quality_sidecar_loaded"])
            self.assertFalse(any("record_quality.jsonl" in ref for ref in out["source_refs"]))
            self.assertEqual(out["sidecar_gaps"][0]["label"], "record_quality")

    def test_attack_class_evidence_applies_quality_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-ac-quality-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            quality = tags_dir.parent / "derived" / "record_quality.jsonl"
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

            out = self._vault().vault_attack_class_evidence(
                attack_class="admin-bypass",
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
            )

            self.assertFalse(out.get("degraded"))
            self.assertTrue(out["quality_sidecar_loaded"])
            self.assertEqual(out["exemplar_verdicts"][0]["record_id"], "dydx/admin-bypass")
            self.assertEqual(out["exemplar_verdicts"][0]["record_tier"], "dydx-filed")
            self.assertEqual(out["exemplar_verdicts"][0]["record_quality_score"], 5.0)

    def test_attack_class_evidence_applies_proof_hardening_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-ac-proof-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            proof = tags_dir.parent / "derived" / "proof_hardening.jsonl"
            record = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/iavl-abba",
                "source_audit_ref": "paste_ready/filed/cantina-202.md",
                "target_language": "go",
                "target_repo": "cosmos/iavl",
                "bug_class": "missing-close-pruning-shutdown-deadlock",
                "attack_class": "graceful-shutdown-deadlock",
                "verdict_class": "FILED",
            }
            _write(index_dir / "by_attack_class.jsonl", json.dumps({"key": "graceful-shutdown-deadlock", "record": record}) + "\n")
            _write(
                proof,
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_hardening.v1",
                        "record_id": "dydx/iavl-abba",
                        "source_audit_ref": "paste_ready/filed/cantina-202.md",
                        "result_class": "discovery_analogy",
                        "advisory_only": True,
                        "promotion_allowed": False,
                        "submission_posture": "NOT_SUBMIT_READY",
                        "triggered_gates": ["L29-FILING", "R30"],
                    }
                )
                + "\n",
            )

            out = self._vault().vault_attack_class_evidence(
                attack_class="graceful-shutdown-deadlock",
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
            )

            self.assertFalse(out.get("degraded"))
            self.assertTrue(out["hackerman_query"]["records"][0]["proof_hardening"]["advisory_only"])
            self.assertFalse(out["records"][0]["proof_hardening"]["promotion_allowed"])
            self.assertEqual(out["exemplar_verdicts"][0]["proof_hardening"]["submission_posture"], "NOT_SUBMIT_READY")

    def test_function_shape_attack_evidence_queries_shape_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-shape-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            shape = "0123456789abcdef"
            _write(
                index_dir / "by_shape_hash.jsonl",
                json.dumps({"key": shape, "tag_file": "shape.yaml", "verdict_id": "rec/shape"}) + "\n",
            )
            _write(index_dir / "by_function_shape.jsonl", "")
            _write(
                tags_dir / "shape.yaml",
                f"""
verdict_id: rec/shape
target_repo: example/go
language: go
verdict_class: FILED
bug_class: fee-redirect
attack_classes_to_try:
  - blocked-addr-fee-redirect
sites:
  - file_path: x/fees/keeper/msg_server.go
    function_signature: "func (k Keeper) Process(ctx sdk.Context, msg *types.MsgProcess) error"
    shape_hash: {shape}
notes: prior shape
""".lstrip(),
            )

            out = self._vault().vault_function_shape_attack_evidence(
                shape_hash=shape,
                target_repo="example/go",
                file_path="x/fees/keeper/msg_server.go",
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
            )

            self.assertFalse(out.get("degraded"))
            self.assertEqual(out["schema"], SERVER.FUNCTION_SHAPE_ATTACK_EVIDENCE_SCHEMA)
            self.assertEqual(out["total_records_matched"], 1)
            self.assertEqual(out["ranked_attack_classes"][0]["attack_class"], "blocked-addr-fee-redirect")
            self.assertEqual(out["evidence_records"][0]["record_id"], "rec/shape")

    def test_function_shape_attack_evidence_applies_quality_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-shape-quality-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            quality = tags_dir.parent / "derived" / "record_quality.jsonl"
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

            out = self._vault().vault_function_shape_attack_evidence(
                shape_hash=shape,
                target_repo="dydxprotocol/v4-chain",
                file_path="protocol/x/auth/keeper/msg_server.go",
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
            )

            self.assertFalse(out.get("degraded"))
            self.assertEqual(out["ranked_attack_classes"][0]["attack_class"], "admin-bypass")
            self.assertEqual(out["evidence_records"][0]["record_id"], "dydx/msg-server-auth")
            self.assertEqual(out["evidence_records"][0]["record_tier"], "dydx-filed")
            self.assertEqual(out["evidence_records"][0]["record_quality_score"], 5.0)

    def test_function_shape_attack_evidence_applies_proof_hardening_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-shape-proof-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            proof = tags_dir.parent / "derived" / "proof_hardening.jsonl"
            shape = "0123456789abcdef"
            record = {
                "schema_version": "auditooor.hackerman_record.v1",
                "record_id": "dydx/iavl-abba",
                "source_audit_ref": "paste_ready/filed/cantina-202.md",
                "target_language": "go",
                "target_repo": "cosmos/iavl",
                "bug_class": "missing-close-pruning-shutdown-deadlock",
                "attack_class": "graceful-shutdown-deadlock",
                "function_shape": {"raw_signature": "func (ndb *nodeDB) deleteLegacyVersions()"},
            }
            _write(index_dir / "by_shape_hash.jsonl", json.dumps({"key": shape, "record": record}) + "\n")
            _write(index_dir / "by_function_shape.jsonl", "")
            _write(
                proof,
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_hardening.v1",
                        "record_id": "dydx/iavl-abba",
                        "source_audit_ref": "paste_ready/filed/cantina-202.md",
                        "result_class": "discovery_analogy",
                        "advisory_only": True,
                        "promotion_allowed": False,
                        "submission_posture": "NOT_SUBMIT_READY",
                        "triggered_gates": ["L29-FILING", "R18", "R19", "R30"],
                    }
                )
                + "\n",
            )

            out = self._vault().vault_function_shape_attack_evidence(
                shape_hash=shape,
                target_repo="cosmos/iavl",
                file_path="iavl/nodedb.go",
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
            )

            self.assertFalse(out.get("degraded"))
            self.assertEqual(out["evidence_records"][0]["proof_hardening"]["result_class"], "discovery_analogy")
            self.assertFalse(out["evidence_records"][0]["proof_hardening"]["promotion_allowed"])
            self.assertIn("R30", out["evidence_records"][0]["proof_hardening"]["triggered_gates"])

    def test_cross_language_pattern_lift_uses_record_analogues(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-xlang-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            row = {
                "record_id": "rec/share",
                "tag_file": "share.yaml",
                "target_language": "solidity",
                "attack_class": "first-deposit-share-inflation",
            }
            _write(index_dir / "by_language.jsonl", json.dumps({"key": "solidity", **row}) + "\n")
            _write(
                tags_dir / "share.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/share
source_audit_ref: audit:share:1
target_domain: lending
target_language: solidity
target_repo: example/vault
target_component: Vault.deposit
function_shape:
  raw_signature: "function deposit(uint256 assets, address receiver) external returns (uint256)"
  shape_tags:
    - external-nonpayable-share-mint-after-asset-transfer
bug_class: share-inflation
attack_class: first-deposit-share-inflation
attacker_role: unprivileged
attacker_action_sequence: "donate then deposit"
required_preconditions: []
impact_class: theft
impact_actor: depositors
impact_dollar_class: "$100K-$1M"
fix_pattern: virtual shares
fix_anti_pattern_avoided: raw balance accounting
severity_at_finding: high
year: 2025
cross_language_analogues:
  - target_language: go
    pattern_translation: "module mints claim units from mutable bank balance"
related_records: []
""".lstrip(),
            )

            out = self._vault().vault_cross_language_pattern_lift(
                source_language="solidity",
                target_language="go",
                attack_class="first-deposit-share-inflation",
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
            )

            self.assertFalse(out.get("degraded"))
            self.assertEqual(out["schema"], SERVER.CROSS_LANGUAGE_PATTERN_LIFT_SCHEMA)
            self.assertEqual(out["total_records_matched"], 1)
            self.assertEqual(out["lift_candidates"][0]["record_id"], "rec/share")
            self.assertIn("mutable bank balance", out["lift_candidates"][0]["pattern_translation"])
            self.assertFalse(out["cross_language_sidecar_loaded"])
            self.assertFalse(any("cross_language_analogues.jsonl" in ref for ref in out["source_refs"]))
            self.assertEqual(out["sidecar_gaps"][0]["label"], "cross_language_analogues")

    def test_cross_language_pattern_lift_uses_derived_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-xlang-sidecar-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            sidecar = tags_dir.parent / "derived" / "cross_language_analogues.jsonl"
            _write(
                index_dir / "by_attack_class.jsonl",
                json.dumps(
                    {
                        "key": "first-deposit-share-inflation",
                        "tag_file": "share.yaml",
                        "record_id": "rec/share",
                    }
                )
                + "\n",
            )
            _write(index_dir / "by_language.jsonl", "")
            _write(
                tags_dir / "share.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/share
source_audit_ref: audit:share:1
target_domain: lending
target_language: solidity
target_repo: example/vault
target_component: Vault.deposit
bug_class: share-inflation
attack_class: first-deposit-share-inflation
attacker_role: unprivileged
attacker_action_sequence: "donate then deposit"
required_preconditions: []
impact_class: theft
impact_actor: depositors
impact_dollar_class: "$100K-$1M"
fix_pattern: virtual shares
fix_anti_pattern_avoided: raw balance accounting
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )
            _write(
                sidecar,
                json.dumps(
                    {
                        "source_record_id": "rec/share",
                        "source_language": "solidity",
                        "target_language": "go",
                        "analogue_record_id": "go/share",
                        "attack_class": "first-deposit-share-inflation",
                        "confidence": 0.91,
                        "pattern_translation": "solidity->go: module mints claim units from mutable bank balance",
                    }
                )
                + "\n",
            )

            out = self._vault().vault_cross_language_pattern_lift(
                source_language="solidity",
                target_language="go",
                attack_class="first-deposit-share-inflation",
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
            )

            self.assertFalse(out.get("degraded"))
            self.assertTrue(out["cross_language_sidecar_loaded"])
            self.assertEqual(out["cross_language_sidecar_sources_loaded"], 1)
            self.assertEqual(out["total_records_matched"], 1)
            self.assertEqual(out["lift_candidates"][0]["record_id"], "rec/share")
            self.assertIn("mutable bank balance", out["lift_candidates"][0]["pattern_translation"])

    def test_cross_language_pattern_lift_accepts_source_language_class_alias(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-xlang-alias-") as tmp:
            root = Path(tmp)
            index_dir = root / "index"
            tags_dir = root / "tags"
            _write(
                index_dir / "by_attack_class.jsonl",
                json.dumps(
                    {
                        "key": "callback-mid-state-mutation",
                        "tag_file": "callback.yaml",
                        "record_id": "rec/callback",
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "key": "post-execution-check-skip",
                        "tag_file": "go-hook.yaml",
                        "record_id": "rec/go-hook",
                    }
                )
                + "\n",
            )
            _write(index_dir / "by_language.jsonl", "")
            _write(
                tags_dir / "callback.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/callback
source_audit_ref: audit:callback:1
target_domain: dex
target_language: solidity
target_repo: example/dex
target_component: Pool.swap
function_shape:
  raw_signature: "function swap(bytes calldata data) external"
  shape_tags:
    - external-callback-mid-state
bug_class: callback-reentrancy
attack_class: callback-mid-state-mutation
attacker_role: unprivileged
attacker_action_sequence: "enter callback while pool state is half-updated"
required_preconditions: []
impact_class: theft
impact_actor: liquidity-providers
impact_dollar_class: "$100K-$1M"
fix_pattern: update state before callback
fix_anti_pattern_avoided: external callback before invariant commit
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )
            _write(
                tags_dir / "go-hook.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/go-hook
source_audit_ref: audit:go-hook:1
target_domain: consensus
target_language: go
target_repo: example/cosmos
target_component: keeper.Confirm
function_shape:
  raw_signature: "func (k Keeper) Confirm(ctx sdk.Context, msg MsgConfirm) error"
  shape_tags:
    - msg-server-hook-post-check
bug_class: hook-bypass
attack_class: post-execution-check-skip
attacker_role: unprivileged
attacker_action_sequence: "trigger keeper hook before the post-execution confirmation check"
required_preconditions: []
impact_class: griefing
impact_actor: protocol-treasury
impact_dollar_class: "$10K-$100K"
fix_pattern: check confirmation before hook effects commit
fix_anti_pattern_avoided: post-execution confirmation after stateful hook
severity_at_finding: high
year: 2026
cross_language_analogues: []
related_records: []
""".lstrip(),
            )

            out = self._vault().vault_cross_language_pattern_lift(
                source_language_class="solidity:reentrancy_external_call",
                target_language="go",
                index_dir=str(index_dir),
                tags_dir=str(tags_dir),
            )

            self.assertFalse(out.get("degraded"))
            self.assertEqual(out["source_language"], "solidity")
            self.assertEqual(out["attack_class"], "reentrancy_external_call")
            self.assertEqual(out["total_records_matched"], 1)
            self.assertEqual(out["lift_candidates"][0]["record_id"], "rec/callback")
            self.assertEqual(out["lift_candidates"][0]["target_language"], "go")
            self.assertEqual(out["target_language_precedents"][0]["record_id"], "rec/go-hook")
            self.assertEqual(out["target_language_precedents"][0]["target_language"], "go")

    def test_new_callables_are_registered(self) -> None:
        names = {tool["name"] for tool in SERVER.TOOL_SCHEMAS}
        self.assertIn("vault_function_shape_attack_evidence", names)
        self.assertIn("vault_cross_language_pattern_lift", names)
        self.assertIn("vault_hackerman_chain_candidates", names)
        self.assertIn("vault_hackerman_detector_relationships", names)
        self.assertIn("vault_hackerman_exploit_predicates", names)
        self.assertIn("vault_hackerman_go_cosmos_inventory", names)
        self.assertIn("vault_hackerman_novel_vector_context", names)
        self.assertIn("vault_loop_finalization_check", names)
        self.assertIn("vault_realworld_recall_gap_priorities", names)
        self.assertIn("vault_audit_deep_manifest_summary", names)
        self.assertEqual(
            self._vault().call("vault_cross_language_pattern_lift", {})["schema"],
            SERVER.CROSS_LANGUAGE_PATTERN_LIFT_SCHEMA,
        )
        self.assertEqual(
            self._vault().call("vault_hackerman_exploit_predicates", {"tag_dir": "/no/such/tags"})["schema"],
            SERVER.HACKERMAN_EXPLOIT_PREDICATES_SCHEMA,
        )
        self.assertEqual(
            self._vault().call("vault_hackerman_novel_vector_context", {"tag_dir": "/no/such/tags"})["schema"],
            SERVER.HACKERMAN_NOVEL_VECTOR_CONTEXT_SCHEMA,
        )
        self.assertEqual(
            self._vault().call("vault_realworld_recall_gap_priorities", {"report_path": "/no/such/file.json"})["schema"],
            SERVER.REALWORLD_RECALL_GAP_PRIORITIES_SCHEMA,
        )
        self.assertEqual(
            self._vault().call("vault_audit_deep_manifest_summary", {"workspace_path": "/no/such/ws"})["schema"],
            SERVER.AUDIT_DEEP_MANIFEST_SUMMARY_SCHEMA,
        )

    def test_toolsite_context_surfaces_novel_vector_callable(self) -> None:
        out = self._vault().vault_toolsite_context(task="novel vector hypotheses", limit=1)
        self.assertFalse(out.get("degraded"))
        self.assertEqual(out["workflows"][0]["id"], "hackerman-novel-vector-hypotheses")
        self.assertIn(
            "vault_hackerman_novel_vector_context",
            out["workflows"][0]["callables"],
        )

    def test_new_recall_wrappers_are_bounded_and_advisory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-realworld-gap-") as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            _write(
                reports / "realworld_recall_gap_priorities.json",
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_gap_priorities.v1",
                        "scoreboard_schema": "auditooor.realworld_recall_scoreboard.v1",
                        "generated_at": "2026-05-17T00:00:00Z",
                        "totals": {"measured_samples": 10},
                        "input_counts": {"scoreboards_loaded": 1},
                        "warnings": [],
                        "priorities": [
                            {
                                "rank": 1,
                                "attack_class": "reentrancy",
                                "priority_band": "P0",
                                "priority_score": 88.0,
                                "same_class_recall": 0.2,
                                "same_class_misses": 4,
                                "gap_vs_self_test_pp": 50.0,
                                "gap_vs_any_pp": 30.0,
                                "next_tasks": [{"task_type": "detector-gap"}],
                            }
                        ],
                        "taxonomy_debt": [
                            {
                                "rank": 1,
                                "attack_class": "uncategorized",
                                "priority_score": 20.0,
                                "same_class_misses": 2,
                                "next_tasks": [{"task_type": "taxonomy-backfill"}],
                            }
                        ],
                    }
                ),
            )
            gap = self._vault().vault_realworld_recall_gap_priorities(report_path=str(reports / "realworld_recall_gap_priorities.json"), limit=1)
            self.assertEqual(gap["schema"], SERVER.REALWORLD_RECALL_GAP_PRIORITIES_SCHEMA)
            self.assertTrue(gap["advisory_only"])
            self.assertEqual(gap["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(gap["priorities_returned"], 1)
            self.assertEqual(gap["top_priorities"][0]["attack_class"], "reentrancy")

        with tempfile.TemporaryDirectory(prefix="vault-hackerman-audit-deep-manifest-") as tmp:
            root = Path(tmp)
            ws = root / "ws"
            (ws / ".audit_logs").mkdir(parents=True)
            _write(
                ws / ".audit_logs" / "audit_deep_manifest_report.json",
                json.dumps(
                    {
                        "schema": "auditooor.audit_deep_manifest_summary.v1",
                        "workspace": str(ws),
                        "counts": {"ran": 3, "failed": 1},
                        "sources": [
                            {
                                "kind": "audit-deep-report",
                                "path": ".audit_logs/audit_deep_report.md",
                                "counts": {"ran": 2},
                                "rows": [{"tool": "halmos", "state": "ran", "raw_status": "ok", "detail": "done"}],
                            }
                        ],
                        "bridge_outputs": {
                            "audit-deep-handoff": [
                                {"path": ".audit_logs/audit_deep_report.md", "status": "present", "purpose": "canonical report"}
                            ]
                        },
                    }
                ),
            )
            summary = self._vault().vault_audit_deep_manifest_summary(workspace_path=str(ws), limit=1)
            self.assertEqual(summary["schema"], SERVER.AUDIT_DEEP_MANIFEST_SUMMARY_SCHEMA)
            self.assertTrue(summary["advisory_only"])
            self.assertEqual(summary["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(summary["sources_returned"], 1)
            self.assertEqual(summary["bridge_groups_returned"], 1)

    def test_hackerman_capability_wrappers_are_bounded_and_advisory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-capabilities-") as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            tag_dir.mkdir()
            _write(
                tag_dir / "accounting.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/accounting
source_audit_ref: findings-go:fixture:accounting
target_domain: consensus
target_language: go
target_repo: sample/cosmos
target_component: Keeper.Settle
function_shape:
  raw_signature: "func (k Keeper) Settle(ctx sdk.Context, msg MsgSettle) error"
  shape_tags:
    - settle
    - accounting
bug_class: state-accounting-drift
attack_class: state-accounting-drift
attacker_role: unprivileged
attacker_action_sequence: "submit a settlement that mutates module accounting before the final invariant check"
required_preconditions:
  - matching engine accepts the settlement message
impact_class: theft
impact_actor: protocol-treasury
impact_dollar_class: "$100K-$1M"
fix_pattern: commit accounting only after the invariant succeeds
fix_anti_pattern_avoided: state mutation before invariant validation
severity_at_finding: high
year: 2026
cross_language_analogues: []
related_records: []
""".lstrip(),
            )
            _write(
                tag_dir / "validation.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/validation
source_audit_ref: findings-go:fixture:validation
target_domain: consensus
target_language: go
target_repo: sample/cosmos
target_component: Keeper.Settle
function_shape:
  raw_signature: "func (k Keeper) Settle(ctx sdk.Context, msg MsgSettle) error"
  shape_tags:
    - settle
    - validation
bug_class: missing-input-validation
attack_class: missing-input-validation
attacker_role: unprivileged
attacker_action_sequence: "submit malformed settlement fields that pass ValidateBasic and reach the keeper"
required_preconditions:
  - keeper path is reachable from a transaction
impact_class: dos
impact_actor: validator-set
impact_dollar_class: "$10K-$100K"
fix_pattern: reject malformed settlement fields before keeper mutation
fix_anti_pattern_avoided: keeper-only validation after mutation
severity_at_finding: medium
year: 2026
cross_language_analogues: []
related_records: []
""".lstrip(),
            )
            engage = root / "engage_report.json"
            _write(
                engage,
                json.dumps(
                    {
                        "clusters": [
                            {
                                "detector_slug": "missing-input-validation-settle",
                                "hits": [
                                    {
                                        "severity": "HIGH",
                                        "file_path": "x/foo/keeper/settle.go:42",
                                        "snippet": "Keeper.Settle writes accounting before input validation",
                                    }
                                ],
                            }
                        ]
                    }
                ),
            )
            manifest = root / "loop_manifest.json"
            _write(
                manifest,
                json.dumps(
                    {
                        "changed_artifacts": ["tools/example.py"],
                        "handoff_or_ledger_updated": {"paths": ["agent_outputs/example.md"]},
                        "agent_outputs_collected": {"paths": ["agent_outputs/example.md"]},
                        "tests_or_logs_linked": {"commands": ["python3 -m unittest example"]},
                        "mcp_memory_updated_when_relevant": {"relevant": False},
                    }
                ),
            )

            vault = self._vault()
            chain = vault.vault_hackerman_chain_candidates(tag_dir=str(tag_dir), limit=3)
            self.assertEqual(chain["schema"], SERVER.HACKERMAN_CHAIN_CANDIDATES_SCHEMA)
            self.assertTrue(chain["advisory_only"])
            self.assertEqual(chain["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(chain["total_records_loaded"], 2)
            self.assertEqual(chain["total_candidates"], 1)
            self.assertEqual(chain["candidates"][0]["group"]["component_anchor"], "keeper.settle")

            detector = vault.vault_hackerman_detector_relationships(
                tag_dir=str(tag_dir),
                engage_report=str(engage),
                limit=2,
            )
            self.assertEqual(detector["schema"], SERVER.HACKERMAN_DETECTOR_RELATIONSHIPS_SCHEMA)
            self.assertTrue(detector["advisory_only"])
            self.assertEqual(detector["summary"]["records_loaded"], 2)
            self.assertEqual(detector["summary"]["detectors_returned"], 1)
            self.assertGreaterEqual(
                detector["detectors"][0]["relationships"][0]["score"],
                1,
            )

            predicates = vault.vault_hackerman_exploit_predicates(
                tag_dir=str(tag_dir),
                record_id="rec/accounting",
                limit=2,
            )
            self.assertEqual(predicates["schema"], SERVER.HACKERMAN_EXPLOIT_PREDICATES_SCHEMA)
            self.assertTrue(predicates["advisory_only"])
            self.assertEqual(predicates["total_records_matched"], 1)
            self.assertEqual(predicates["records"][0]["record_id"], "rec/accounting")
            self.assertLessEqual(len(predicates["records"][0]["predicates"]), 16)

            inventory = vault.vault_hackerman_go_cosmos_inventory(
                tag_dir=str(tag_dir),
                reference_root=str(root),
                limit=2,
            )

            self.assertEqual(inventory["schema"], SERVER.HACKERMAN_GO_COSMOS_INVENTORY_SCHEMA)
            self.assertTrue(inventory["advisory_only"])
            self.assertEqual(inventory["summary"]["tag_records_go_cosmos"], 2)
            self.assertEqual(inventory["candidate_import_targets"], [])

            closeout = vault.vault_loop_finalization_check(manifest_path=str(manifest))
            self.assertEqual(closeout["schema"], SERVER.LOOP_FINALIZATION_CHECK_WRAPPER_SCHEMA)
            self.assertTrue(closeout["advisory_only"])
            self.assertEqual(closeout["status"], "pass")
            self.assertTrue(closeout["passed"])

    def test_hackerman_novel_vector_context_is_bounded_and_advisory(self) -> None:
        hypotheses = []
        for idx in range(1, 61):
            hypotheses.append(
                {
                    "schema": "auditooor.hackerman_novel_vector_hypothesis.v1",
                    "hypothesis_id": f"novelvec:{idx:03d}",
                    "generation_mode": "same_class_variant_advisory" if idx == 1 else "residual_novel_class",
                    "rank": idx,
                    "advisory_only": True,
                    "target_repo": "example/repo",
                    "target_domain": "dex",
                    "target_language": "solidity",
                    "target_component": f"Vault.swap{idx}",
                    "target_signature": "function swap(uint256 amount) external",
                    "shape_tags": ["swap", "fee"],
                    "novel_attack_class": "fee-redirect",
                    "novel_bug_class": "missing-fee-sink-auth",
                    "repo_attack_classes_seen": ["state-drift"],
                    "nearest_analogue": {
                        "record_id": f"remote/{idx}",
                        "source_audit_ref": f"audit:remote:{idx}",
                        "target_repo": "peer/repo",
                        "target_component": "Router.swap",
                        "target_signature": "function swap(uint256 amount) external",
                        "bug_class": "missing-fee-sink-auth",
                        "attack_class": "fee-redirect",
                        "impact_class": "theft",
                        "severity_at_finding": "high",
                        "shape_tags": ["swap", "fee"],
                    },
                    "preconditions": [{"kind": "state_token", "value": "state:fee-sink"}],
                    "possible_chain": [
                        {
                            "step_index": 1,
                            "step_type": "local_bridge",
                            "record_id": "local/bridge",
                            "attack_class": "state-drift",
                            "bug_class": "state-drift",
                            "target_component": "Vault.settle",
                            "matched_state": ["state:fee-sink"],
                            "narrative": "bridge",
                        },
                        {
                            "step_index": 2,
                            "step_type": "hypothesis",
                            "record_id": "",
                            "attack_class": "fee-redirect",
                            "bug_class": "missing-fee-sink-auth",
                            "target_component": "Vault.swap",
                            "matched_state": ["state:fee-sink"],
                            "narrative": "hypothesis",
                        },
                    ],
                    "proof_obligations": [
                        {"kind": "shape_match", "obligation": "prove shape", "evidence_hint": "source trace"}
                    ],
                    "score": float(100 - idx),
                    "score_breakdown": {"score": float(100 - idx)},
                    "same_class_variant": {
                        "mode": "same_class_variant_advisory",
                        "signals": ["distinct_target_component"],
                        "max_local_shape_overlap": 0.5,
                        "local_same_class_count": 2,
                    } if idx == 1 else {},
                    "novelty_rationale": "advisory-only",
                    "limitations": ["advisory only"],
                }
            )
        fake_payload = {
            "schema": "auditooor.hackerman_novel_vector_hypotheses.summary.v1",
            "total_records": 200,
            "total_target_candidates": 120,
            "targets_considered": 120,
            "target_scan_limit": 120,
            "targets_truncated": True,
            "target_selection_preview": [
                {
                    "record_id": f"target/{idx}",
                    "target_repo": "example/repo",
                    "target_component": f"Vault.swap{idx}",
                    "target_language": "solidity",
                    "target_domain": "dex",
                    "selection_score": float(200 - idx),
                    "selection_breakdown": {
                        "score": float(200 - idx),
                        "analogue_pool": 10.0,
                    },
                }
                for idx in range(1, 20)
            ],
            "filtered_target_repo": 3,
            "filtered_target_language": 4,
            "filtered_target_domain": 5,
            "filtered_target_missing_shape": 6,
            "candidate_pairs_seen": 120,
            "candidate_pairs_considered": 80,
            "filtered_same_repo": 10,
            "filtered_min_shape_overlap": 11,
            "filtered_existing_class": 30,
            "same_class_variant_mode": True,
            "same_class_variant_candidates": 7,
            "same_class_variants_emitted": 3,
            "filtered_no_bridge": 20,
            "total_hypotheses": 60,
            "hypotheses": hypotheses,
            "diagnostics": {
                "empty_state": {
                    "status": "empty",
                    "reasons": ["not enough shape overlap"],
                    "next_steps": ["increase --max-targets"],
                }
            },
            "limitations": ["advisory output only"],
        }

        original_builder = SERVER.VaultQuery._build_hackerman_novel_vector_payload
        captured_kwargs: dict[str, object] = {}

        def _fake_builder(self, **_kwargs):
            captured_kwargs.update(_kwargs)
            return fake_payload

        SERVER.VaultQuery._build_hackerman_novel_vector_payload = _fake_builder
        try:
            out = self._vault().vault_hackerman_novel_vector_context(
                limit=999,
                target_repo="example/repo",
                language="solidity",
                domain="dex",
                max_targets=999,
                same_class_variants=True,
            )
        finally:
            SERVER.VaultQuery._build_hackerman_novel_vector_payload = original_builder

        self.assertEqual(out["schema"], SERVER.HACKERMAN_NOVEL_VECTOR_CONTEXT_SCHEMA)
        self.assertTrue(out["advisory_only"])
        self.assertEqual(out["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(out["inputs"]["limit"], SERVER.MAX_LIMIT)
        self.assertEqual(
            out["inputs"]["max_targets"],
            SERVER.MAX_HACKERMAN_NOVEL_VECTOR_MAX_TARGETS,
        )
        self.assertTrue(out["inputs"]["same_class_variants"])
        self.assertTrue(captured_kwargs["same_class_variants"])
        self.assertEqual(out["total_hypotheses"], 60)
        self.assertEqual(out["hypotheses_returned"], SERVER.MAX_LIMIT)
        self.assertEqual(len(out["hypotheses"]), SERVER.MAX_LIMIT)
        self.assertEqual(out["hypotheses"][0]["hypothesis_id"], "novelvec:001")
        self.assertEqual(out["hypotheses"][0]["generation_mode"], "same_class_variant_advisory")
        self.assertEqual(out["hypotheses"][0]["same_class_variant"]["signals"], ["distinct_target_component"])
        self.assertEqual(out["candidate_pairs_seen"], 120)
        self.assertEqual(out["filtered_same_repo"], 10)
        self.assertEqual(out["filtered_min_shape_overlap"], 11)
        self.assertEqual(out["filtered_target_repo"], 3)
        self.assertTrue(out["same_class_variant_mode"])
        self.assertEqual(out["same_class_variant_candidates"], 7)
        self.assertEqual(out["same_class_variants_emitted"], 3)
        self.assertEqual(len(out["target_selection_preview"]), 12)
        self.assertEqual(out["target_selection_preview"][0]["record_id"], "target/1")
        self.assertEqual(out["diagnostics"]["empty_state"]["status"], "empty")
        self.assertIn("increase --max-targets", out["diagnostics"]["empty_state"]["next_steps"])
        self.assertIn("tools/hackerman-novel-vector-gen.py", out["source_refs"])

    def test_hackerman_chain_candidates_prefers_fresh_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-chain-sidecar-") as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            tag_dir.mkdir()
            _write(
                tag_dir / "access.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/access
source_audit_ref: audit:test:access
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: contracts/Vault.sol
function_shape:
  raw_signature: "function deposit(uint256 assets, address receiver) external"
  shape_tags:
    - deposit-shape-a
bug_class: access-control
attack_class: access-control-missing-modifier
attacker_role: unprivileged
attacker_action_sequence: "shared deposit surface"
required_preconditions:
  - shared anchor exists
impact_class: theft
impact_actor: depositor-class
impact_dollar_class: "$10K-$100K"
fix_pattern: unrelated mitigation
fix_anti_pattern_avoided: unrelated anti-pattern
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )
            _write(
                tag_dir / "oracle.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/oracle
source_audit_ref: audit:test:oracle
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: contracts/Vault.sol
function_shape:
  raw_signature: "function deposit(uint256 assets, address receiver) external"
  shape_tags:
    - deposit-shape-b
bug_class: stale-oracle
attack_class: oracle-staleness
attacker_role: unprivileged
attacker_action_sequence: "shared deposit surface"
required_preconditions:
  - shared anchor exists
impact_class: theft
impact_actor: depositor-class
impact_dollar_class: "$10K-$100K"
fix_pattern: unrelated mitigation
fix_anti_pattern_avoided: unrelated anti-pattern
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )
            chain_sidecar = root / "derived" / "chain_candidates.jsonl"
            chain_unify_sidecar = root / "derived" / "chain_unify_payload.json"
            CHAIN_SIDECAR.build_sidecar(tag_dir, chain_sidecar)
            CHAIN_UNIFY_SIDECAR.build_sidecar(
                tag_dir,
                chain_unify_sidecar,
                chain_sidecar_path=chain_sidecar,
            )

            unify_mod = SERVER.VaultQuery._load_hackerman_query_module(
                "hackerman-chain-unify.py", "_vault_hackerman_chain_unify"
            )
            original_build_payload = unify_mod.build_payload
            original_build_payload_from_rows = unify_mod.build_payload_from_chain_candidate_rows

            def _should_not_call(*_args, **_kwargs):
                raise AssertionError("live chain-unify build path should not run with fresh payload sidecar")

            unify_mod.build_payload = _should_not_call
            unify_mod.build_payload_from_chain_candidate_rows = _should_not_call
            try:
                chain = self._vault().vault_hackerman_chain_candidates(tag_dir=str(tag_dir), limit=3)
            finally:
                unify_mod.build_payload = original_build_payload
                unify_mod.build_payload_from_chain_candidate_rows = original_build_payload_from_rows
            self.assertEqual(chain["schema"], SERVER.HACKERMAN_CHAIN_CANDIDATES_SCHEMA)
            self.assertTrue(chain["advisory_only"])
            self.assertTrue(chain["sidecar_used"])
            self.assertEqual(chain["sidecar_status"], "fresh")
            self.assertIn("chain_candidates.jsonl", chain["sidecar_path"])
            self.assertTrue(chain["chain_unify_sidecar_used"])
            self.assertEqual(chain["chain_unify_sidecar_status"], "fresh")
            self.assertIn("chain_unify_payload.json", chain["chain_unify_sidecar_path"])
            self.assertEqual(chain["sidecar_gaps"], [])
            self.assertEqual(chain["total_records_loaded"], 2)
            self.assertEqual(chain["total_candidates"], 1)

    def test_hackerman_chain_candidates_reports_sidecar_gap_when_stale(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-chain-sidecar-stale-") as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            tag_dir.mkdir()
            _write(
                tag_dir / "access.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/access
source_audit_ref: audit:test:access
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: contracts/Vault.sol
function_shape:
  raw_signature: "function deposit(uint256 assets, address receiver) external"
  shape_tags:
    - deposit-shape-a
bug_class: access-control
attack_class: access-control-missing-modifier
attacker_role: unprivileged
attacker_action_sequence: "shared deposit surface"
required_preconditions:
  - shared anchor exists
impact_class: theft
impact_actor: depositor-class
impact_dollar_class: "$10K-$100K"
fix_pattern: unrelated mitigation
fix_anti_pattern_avoided: unrelated anti-pattern
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )
            CHAIN_SIDECAR.build_sidecar(tag_dir, root / "derived" / "chain_candidates.jsonl")
            _write(
                tag_dir / "oracle.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/oracle
source_audit_ref: audit:test:oracle
target_domain: vault
target_language: solidity
target_repo: example/protocol
target_component: contracts/Vault.sol
function_shape:
  raw_signature: "function deposit(uint256 assets, address receiver) external"
  shape_tags:
    - deposit-shape-b
bug_class: stale-oracle
attack_class: oracle-staleness
attacker_role: unprivileged
attacker_action_sequence: "shared deposit surface"
required_preconditions:
  - shared anchor exists
impact_class: theft
impact_actor: depositor-class
impact_dollar_class: "$10K-$100K"
fix_pattern: unrelated mitigation
fix_anti_pattern_avoided: unrelated anti-pattern
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )

            chain = self._vault().vault_hackerman_chain_candidates(tag_dir=str(tag_dir), limit=3)
            self.assertFalse(chain["sidecar_used"])
            self.assertFalse(chain["chain_unify_sidecar_used"])
            self.assertTrue(chain["sidecar_gaps"])
            self.assertEqual(chain["sidecar_gaps"][0]["label"], "chain_candidates")

    def test_hackerman_detector_relationships_prefers_fresh_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-hackerman-detector-sidecar-") as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            tag_dir.mkdir()
            _write(
                tag_dir / "fee.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/fee
source_audit_ref: audit:test:fee
target_domain: chain
target_language: go
target_repo: example/chain
target_component: keeper.settle
function_shape:
  raw_signature: "func (k Keeper) Settle(ctx sdk.Context) error"
  shape_tags:
    - settle-path
bug_class: missing-blocked-address-check
attack_class: blocked-addr-fee-redirect
attacker_role: unprivileged
attacker_action_sequence: "redirect fee recipient"
required_preconditions:
  - recipient field is attacker controlled
impact_class: theft
impact_actor: fee sink
impact_dollar_class: "$10K-$100K"
fix_pattern: enforce blocked-address validation before write
fix_anti_pattern_avoided: store write before authz validation
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )
            _write(
                tag_dir / "share.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: rec/share
source_audit_ref: audit:test:share
target_domain: lending
target_language: solidity
target_repo: example/vault
target_component: Vault.deposit
function_shape:
  raw_signature: "function deposit(uint256 assets) external"
  shape_tags:
    - deposit-path
bug_class: share-inflation
attack_class: share-price-manipulation
attacker_role: unprivileged
attacker_action_sequence: "donate before victim deposit"
required_preconditions:
  - donation shifts exchange rate
impact_class: theft
impact_actor: depositor-class
impact_dollar_class: "$10K-$100K"
fix_pattern: internal accounting snapshot
fix_anti_pattern_avoided: live balance pricing
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )
            engage = root / "engage_report.json"
            _write(
                engage,
                json.dumps(
                    {
                        "clusters": [
                            {
                                "detector_slug": "blocked-addr-check-missing",
                                "hits": [
                                    {
                                        "severity": "MEDIUM",
                                        "file_path": "x/fees/keeper/keeper.go:88",
                                        "snippet": "keeper writes affiliate recipient without blocked address validation",
                                    }
                                ],
                            }
                        ]
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            DETECTOR_SIDECAR.build_sidecar(
                tag_dir,
                root / "derived" / "detector_relationship_records.jsonl",
            )

            detector = self._vault().vault_hackerman_detector_relationships(
                tag_dir=str(tag_dir),
                engage_report=str(engage),
                limit=3,
            )

            self.assertEqual(detector["schema"], SERVER.HACKERMAN_DETECTOR_RELATIONSHIPS_SCHEMA)
            self.assertTrue(detector["advisory_only"])
            self.assertTrue(detector["sidecar_used"])
            self.assertEqual(detector["sidecar_status"], "fresh")
            self.assertIn("detector_relationship_records.jsonl", detector["sidecar_path"])
            self.assertEqual(detector["summary"]["records_loaded"], 2)
            self.assertEqual(detector["summary"]["detectors_returned"], 1)
            self.assertEqual(
                detector["detectors"][0]["relationships"][0]["record_id"],
                "rec/fee",
            )


if __name__ == "__main__":
    unittest.main()
